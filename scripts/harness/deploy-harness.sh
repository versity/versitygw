#!/bin/bash
# Build the v3 E2E harness clients on this host and copy them to
# guest VM2's /root/harness. Usage: deploy-harness.sh <guest-password>
# (or set GUEST_PW in the environment). Runs from the gate host that
# shares the qemu forwards for ports 2223/2224.
set -e
cd "$(dirname "$0")"

gcc -O2 -Wall -o v3-data-client v3-data-client.c -libverbs -lrdmacm -lcrypto
gcc -O2 -Wall -o v3-data-client-oob v3-data-client-oob.c -libverbs -lcrypto

PW="${1:-$GUEST_PW}"
if [ -z "$PW" ]; then
	echo "usage: $0 <guest-password>" >&2
	exit 1
fi
sshpass -p "$PW" scp -q -P 2224 -o StrictHostKeyChecking=no \
	v3-data-client v3-data-client-oob batesste@localhost:/tmp/
sshpass -p "$PW" ssh -o StrictHostKeyChecking=no -p 2224 batesste@localhost \
	"sudo mv /tmp/v3-data-client /tmp/v3-data-client-oob /root/harness/"
echo "deployed: /root/harness/{v3-data-client,v3-data-client-oob}"
