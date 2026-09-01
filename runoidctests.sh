#!/usr/bin/env bash
#
# Run the test groups that need a real, signed OIDC ID token.
#
# AssumeRoleWithWebIdentity verifies a token's signature against its issuer's
# live JWKS, so these tests need a genuine identity provider rather than a
# fake token. GitHub Actions' own OIDC issuer is the one publicly reachable
# IdP available from inside CI, and only a job holding `id-token: write` can
# mint a token from it — which is why this script lives behind
# .github/workflows/functional-iam-oidc.yml rather than the general
# functional suite. Outside such a job the tests skip themselves, so running
# this locally is harmless but proves little.
#
# It brings up two processes: a standalone IAM service holding every user,
# role, policy and secret, and an s3 gateway that reaches its private
# endpoints over mTLS for signing keys and policy decisions.

set -Eeuo pipefail

readonly IAM_PORT=7078
readonly IAM_PRIVATE_PORT=7079
readonly GW_PORT=7077

readonly IAM_DIR=/tmp/iam-oidc
readonly GW_DIR=/tmp/s3iam-oidc-gw
readonly CERT_DIR=/tmp/s3iam-oidc-certs

IAM_PID=""
GW_PID=""

cleanup() {
	local status=$?
	trap - EXIT
	for pid in "$GW_PID" "$IAM_PID"; do
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
		fi
		if [[ -n "$pid" ]]; then
			wait "$pid" 2>/dev/null || true
		fi
	done
	exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_server() {
	local name="$1"
	local url="$2"
	local pid="$3"

	for _ in {1..50}; do
		if curl --fail --silent --max-time 1 "$url" >/dev/null 2>&1; then
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "$name stopped before becoming ready" >&2
			wait "$pid" 2>/dev/null || true
			return 1
		fi
		sleep 0.2
	done

	echo "timed out waiting for $name at $url" >&2
	return 1
}

rm -rf "$IAM_DIR" "$GW_DIR" "$CERT_DIR"
mkdir -p "$IAM_DIR" "$GW_DIR"

# The gateway verifies the IAM service's certificate normally, with no
# hostname override, so the server certificate needs an IP SAN matching the
# address --iam-standalone-endpoint names.
./genmtlscerts.sh "$CERT_DIR" 127.0.0.1

echo "Starting the standalone IAM service"
./versitygw --health /healthz -p ":$IAM_PORT" -a user -s pass iam \
	--dir "$IAM_DIR" \
	--private-ports "127.0.0.1:$IAM_PRIVATE_PORT" \
	--private-cert "$CERT_DIR/iam-server.pem" \
	--private-cert-key "$CERT_DIR/iam-server.key" \
	--private-client-ca "$CERT_DIR/ca.pem" &
IAM_PID=$!
wait_for_server "IAM API server" "http://127.0.0.1:$IAM_PORT/healthz" "$IAM_PID"

echo "Starting the s3 gateway backed by it"
./versitygw --health /healthz -p ":$GW_PORT" -a user -s pass \
	--iam-standalone-endpoint "127.0.0.1:$IAM_PRIVATE_PORT" \
	--iam-standalone-client-cert "$CERT_DIR/gw-client.pem" \
	--iam-standalone-client-cert-key "$CERT_DIR/gw-client.key" \
	--iam-standalone-server-ca "$CERT_DIR/ca.pem" \
	posix "$GW_DIR" &
GW_PID=$!
wait_for_server "s3 gateway" "http://127.0.0.1:$GW_PORT/healthz" "$GW_PID"

echo "Running the tests that need a real OIDC identity provider"
./versitygw test -a user -s pass \
	-e "http://127.0.0.1:$GW_PORT" \
	--iam-endpoint "http://127.0.0.1:$IAM_PORT" \
	s3-iam-session
