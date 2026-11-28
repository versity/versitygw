#!/bin/bash
# Run the hipobj-rc-v3 out-of-band E2E on the two-VM rocm-ernic
# emulator topology. Assumes the mesh (restart-mesh-only.sh) and the
# guests (boot-guests.sh) are already up on the gate host.
#
# Pass criteria:
#   PUT  status 200, reply 200:<len-hex16>
#   GET  status 200, reply 200:<len-hex16>, region verified
#   failure gate: gateway stopped mid-transfer -> client exit 3
#   CM regression: plain S3 PUT/GET still 200 without the oob flag
set -e
cd "$(dirname "$0")/../.."

G1() { sshpass -p changeme ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no -p 2223 batesste@localhost "$@"; }
G2() { sshpass -p changeme ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no -p 2224 batesste@localhost "$@"; }

# 1. Build + deploy gateway and clients.
make vgwrdma
sshpass -p changeme scp -q -P 2223 -o StrictHostKeyChecking=no vgwrdma batesste@localhost:/tmp/
G1 'sudo mv /tmp/vgwrdma /root/vgwrdma-oob'
bash scripts/harness/deploy-harness.sh changeme

# 2. Start the gateway with the oob transport. LD_LIBRARY_PATH
#    covers the guest-side libcuobjserver install.
G1 'sudo systemctl stop vgw-oob 2>/dev/null || true'
G1 'sudo mkdir -p /tmp/v3data'
G1 'sudo systemd-run --unit=vgw-oob --collect --property=StandardOutput=journal --setenv=LD_LIBRARY_PATH=/usr/local/lib /root/vgwrdma-oob --port :9000 --access hipobj-test-key --secret hipobj-test-secret --region us-east-1 --access-log /tmp/access-oob.log --rdma-rc-enable --rc-transport oob posix /tmp/v3data'
# 3. oob PUT + GET. The harness lives under /root, so the calls
#    ride sudo; 403 on the anonymous health probe means the server
#    is up and authenticating. The bucket is created fresh each run
#    (the gateway's posix root starts empty).
G1 'curl -s -o /dev/null -w "health: %{http_code} (403 = up, anon denied)\n" http://127.0.0.1:9000/' 2>/dev/null || true
G2 'python3 - << "PYEOF"
import hmac, hashlib, datetime, urllib.request
ak, sk = "hipobj-test-key", "hipobj-test-secret"
t = datetime.datetime.now(datetime.timezone.utc)
date, ts = t.strftime("%Y%m%d"), t.strftime("%Y%m%dT%H%M%SZ")
scope = f"{date}/us-east-1/s3/aws4_request"
payload = hashlib.sha256(b"").hexdigest()
canon = f"PUT\n/v3e2ebucket\n\nhost:192.168.200.10:9000\nx-amz-content-sha256:{payload}\nx-amz-date:{ts}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
sts = f"AWS4-HMAC-SHA256\n{ts}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
def sign(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
k = sign(sign(sign(sign(("AWS4"+sk).encode(), date), "us-east-1"), "s3"), "aws4_request")
sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
req = urllib.request.Request("http://192.168.200.10:9000/v3e2ebucket", method="PUT", headers={
  "Host": "192.168.200.10:9000", "x-amz-date": ts, "x-amz-content-sha256": payload,
  "Authorization": f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={sig}"})
print("bucket:", urllib.request.urlopen(req).status)
PYEOF' || G2 'python3 - << "PYEOF"
import hmac, hashlib, datetime, urllib.request, urllib.error
ak, sk = "hipobj-test-key", "hipobj-test-secret"
t = datetime.datetime.now(datetime.timezone.utc)
date, ts = t.strftime("%Y%m%d"), t.strftime("%Y%m%dT%H%M%SZ")
scope = f"{date}/us-east-1/s3/aws4_request"
payload = hashlib.sha256(b"").hexdigest()
canon = f"HEAD\n/v3e2ebucket\n\nhost:192.168.200.10:9000\nx-amz-content-sha256:{payload}\nx-amz-date:{ts}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
sts = f"AWS4-HMAC-SHA256\n{ts}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
def sign(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
k = sign(sign(sign(sign(("AWS4"+sk).encode(), date), "us-east-1"), "s3"), "aws4_request")
sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
req = urllib.request.Request("http://192.168.200.10:9000/v3e2ebucket", method="HEAD", headers={
  "Host": "192.168.200.10:9000", "x-amz-date": ts, "x-amz-content-sha256": payload,
  "Authorization": f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={sig}"})
try:
    print("bucket: exists (HEAD", urllib.request.urlopen(req).status, ")")
except urllib.error.HTTPError as e:
    print("bucket: HEAD", e.code)
PYEOF'
echo "=== oob PUT ==="
G2 'sudo /root/harness/v3-data-client-oob 192.168.200.20 put v3e2ebucket k1 4096 192.168.200.10'
echo "=== oob GET ==="
G2 'sudo /root/harness/v3-data-client-oob 192.168.200.20 get v3e2ebucket k1 4096 192.168.200.10'

# 4. Failure gate: kill the gateway mid-transfer.
echo "=== failure gate (gateway stop mid-PUT) ==="
G2 'sudo timeout 40 /root/harness/v3-data-client-oob 192.168.200.20 put v3e2ebucket kbig 33554432 192.168.200.10; echo "client exit: $?"' &
CL=$!
sleep 1
G1 'sudo systemctl stop vgw-oob'
wait $CL || true

# 5. CM regression: plain SigV4 round-trip without the oob flag.
#    curl basic-auth is not a valid probe here; the gateway
#    requires SigV4, so the check signs like the harness does.
echo "=== CM regression (plain S3) ==="
G1 'sudo systemctl stop vgw-cm 2>/dev/null || true'
G1 'sudo systemd-run --unit=vgw-cm --collect --property=StandardOutput=journal --setenv=LD_LIBRARY_PATH=/usr/local/lib /root/vgwrdma-oob --port :9000 --access hipobj-test-key --secret hipobj-test-secret --region us-east-1 --access-log /tmp/access-cm.log --rdma-rc-enable posix /tmp/v3data' >/dev/null
sleep 3
G2 'python3 - << "PYEOF"
import hmac, hashlib, datetime, urllib.request, urllib.error
ak, sk = "hipobj-test-key", "hipobj-test-secret"
body = b"cm-regression-probe" * 100
t = datetime.datetime.now(datetime.timezone.utc)
date, ts = t.strftime("%Y%m%d"), t.strftime("%Y%m%dT%H%M%SZ")
scope = f"{date}/us-east-1/s3/aws4_request"
payload = hashlib.sha256(body).hexdigest()
def hdrs(p):
    return {"Host": "192.168.200.10:9000", "x-amz-date": ts, "x-amz-content-sha256": p,
            "Authorization": f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={sig}"}
def sign(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
k = sign(sign(sign(sign(("AWS4"+sk).encode(), date), "us-east-1"), "s3"), "aws4_request")
canon = f"PUT\n/v3e2ebucket/cmprobe\n\nhost:192.168.200.10:9000\nx-amz-content-sha256:{payload}\nx-amz-date:{ts}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
sts = f"AWS4-HMAC-SHA256\n{ts}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
req = urllib.request.Request("http://192.168.200.10:9000/v3e2ebucket/cmprobe", data=body, method="PUT", headers=hdrs(payload))
try:
    put = urllib.request.urlopen(req).status
except urllib.error.HTTPError as e:
    put = e.code
p2 = hashlib.sha256(b"").hexdigest()
canon = f"GET\n/v3e2ebucket/cmprobe\n\nhost:192.168.200.10:9000\nx-amz-content-sha256:{p2}\nx-amz-date:{ts}\n\nhost;x-amz-content-sha256;x-amz-date\n{p2}"
sts = f"AWS4-HMAC-SHA256\n{ts}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
req = urllib.request.Request("http://192.168.200.10:9000/v3e2ebucket/cmprobe", method="GET", headers=hdrs(p2))
try:
    r = urllib.request.urlopen(req)
    got = r.read()
    print(f"plain PUT: {put} / plain GET: {r.status} roundtrip:", "PASS" if got == body else "FAIL")
except urllib.error.HTTPError as e:
    print(f"plain PUT: {put} / plain GET: {e.code} roundtrip: FAIL")
PYEOF'
G1 'sudo systemctl stop vgw-cm'
echo "E2E script complete"
