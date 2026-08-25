#!/usr/bin/env bash

set -Eeuo pipefail

IAM_PID=""
IAM_HTTPS_PID=""
IAM_VAULT_PID=""
CERT_DIR=""

stop_process() {
	local pid="${1:-}"
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
	fi
	if [[ -n "$pid" ]]; then
		wait "$pid" 2>/dev/null || true
	fi
}

cleanup() {
	local status=$?
	trap - EXIT
	stop_process "$IAM_VAULT_PID"
	stop_process "$IAM_HTTPS_PID"
	stop_process "$IAM_PID"
	if [[ -n "$CERT_DIR" ]]; then
		rm -rf "$CERT_DIR"
	fi
	exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_server() {
	local name="$1"
	local url="$2"
	local pid="$3"
	shift 3

	for _ in {1..50}; do
		if curl --fail --silent --max-time 1 "$@" "$url" >/dev/null 2>&1; then
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

for tool in curl jq openssl; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "required command not found: $tool" >&2
		exit 1
	fi
done

# Create fresh data and coverage directories for each run.
rm -rf /tmp/iam /tmp/iam-https \
	/tmp/iam.covdata /tmp/iam.https.covdata /tmp/iam.vault.covdata
mkdir -p /tmp/iam /tmp/iam-https \
	/tmp/iam.covdata /tmp/iam.https.covdata /tmp/iam.vault.covdata

CERT_DIR=$(mktemp -d)
echo "Generating a temporary TLS certificate"
openssl genpkey -algorithm RSA -out "$CERT_DIR/key.pem" -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
	-days 1 -subj "/C=US/ST=California/L=San Francisco/O=Versity/OU=Software/CN=versity.com"

echo "Running IAM API integration tests over HTTP"
GOCOVERDIR=/tmp/iam.covdata ./versitygw --health /healthz -p :7075 -a user -s pass \
	iam --dir /tmp/iam &
IAM_PID=$!
wait_for_server "IAM API HTTP server" "http://127.0.0.1:7075/healthz" "$IAM_PID"
./versitygw test -a user -s pass -e http://127.0.0.1:7075 iam
stop_process "$IAM_PID"
IAM_PID=""

echo "Running IAM API integration tests over HTTPS"
GOCOVERDIR=/tmp/iam.https.covdata ./versitygw --health /healthz \
	--cert "$CERT_DIR/cert.pem" --key "$CERT_DIR/key.pem" \
	-p :7076 -a user -s pass iam --dir /tmp/iam-https &
IAM_HTTPS_PID=$!
wait_for_server "IAM API HTTPS server" "https://127.0.0.1:7076/healthz" "$IAM_HTTPS_PID" --insecure
./versitygw test --allow-insecure -a user -s pass -e https://127.0.0.1:7076 iam
stop_process "$IAM_HTTPS_PID"
IAM_HTTPS_PID=""

# Vault is provided by the GitHub Actions service container. The root token is
# used only to provision a least-privilege AppRole for the IAM API under test.
readonly VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
: "${VAULT_TOKEN:?VAULT_TOKEN must contain a Vault provisioning token}"
readonly VAULT_PROVISION_TOKEN="$VAULT_TOKEN"
unset VAULT_TOKEN
readonly VAULT_MOUNT_PATH="kv"
readonly VAULT_SECRET_PATH="iam"
readonly VAULT_POLICY_NAME="iam-api-tests"
readonly VAULT_ROLE_NAME="iam-api-tests"

vault_request() {
	local method="$1"
	local path="$2"
	local data="${3:-}"
	local args=(
		--fail
		--silent
		--show-error
		--request "$method"
		--header "X-Vault-Token: $VAULT_PROVISION_TOKEN"
	)

	if [[ -n "$data" ]]; then
		args+=(--header "Content-Type: application/json" --data "$data")
	fi

	curl "${args[@]}" "${VAULT_ADDR%/}/v1/$path"
}

echo "Waiting for Vault"
for _ in {1..30}; do
	if curl --fail --silent --max-time 1 "${VAULT_ADDR%/}/v1/sys/health" >/dev/null 2>&1; then
		break
	fi
	sleep 0.5
done
curl --fail --silent --show-error "${VAULT_ADDR%/}/v1/sys/health" >/dev/null

echo "Provisioning Vault KV v2 and AppRole"
vault_mounts=$(vault_request GET sys/mounts)
if jq -e --arg mount "$VAULT_MOUNT_PATH/" '.data[$mount] == null' <<<"$vault_mounts" >/dev/null; then
	vault_request POST "sys/mounts/$VAULT_MOUNT_PATH" \
		'{"type":"kv","options":{"version":"2"}}' >/dev/null
elif ! jq -e --arg mount "$VAULT_MOUNT_PATH/" \
	'.data[$mount].type == "kv" and .data[$mount].options.version == "2"' \
	<<<"$vault_mounts" >/dev/null; then
	echo "Vault mount $VAULT_MOUNT_PATH exists but is not KV v2" >&2
	exit 1
fi

vault_auth_methods=$(vault_request GET sys/auth)
if jq -e '.data["approle/"] == null' <<<"$vault_auth_methods" >/dev/null; then
	vault_request POST sys/auth/approle '{"type":"approle"}' >/dev/null
fi

vault_policy=$(printf '%s\n' \
	"path \"$VAULT_MOUNT_PATH/data/$VAULT_SECRET_PATH/*\" { capabilities = [\"create\", \"update\", \"read\"] }" \
	"path \"$VAULT_MOUNT_PATH/metadata/$VAULT_SECRET_PATH/\" { capabilities = [\"list\"] }" \
	"path \"$VAULT_MOUNT_PATH/metadata/$VAULT_SECRET_PATH/*\" { capabilities = [\"delete\", \"list\"] }")
vault_policy_payload=$(jq -nc --arg policy "$vault_policy" '{policy: $policy}')
vault_request PUT "sys/policies/acl/$VAULT_POLICY_NAME" "$vault_policy_payload" >/dev/null

vault_role_payload=$(jq -nc --arg policy "$VAULT_POLICY_NAME" '{
	token_policies: [$policy],
	token_no_default_policy: true,
	token_ttl: "5m",
	token_max_ttl: "15m",
	secret_id_ttl: "15m"
}')
vault_request POST "auth/approle/role/$VAULT_ROLE_NAME" "$vault_role_payload" >/dev/null

vault_role_id=$(vault_request GET "auth/approle/role/$VAULT_ROLE_NAME/role-id" | jq -er '.data.role_id')
vault_role_secret=$(vault_request POST "auth/approle/role/$VAULT_ROLE_NAME/secret-id" | jq -er '.data.secret_id')

echo "Running IAM API integration tests with the Vault backend"
VGW_IAM_VAULT_ROLE_SECRET="$vault_role_secret" \
	GOCOVERDIR=/tmp/iam.vault.covdata ./versitygw --health /healthz -p :7077 -a user -s pass iam \
	--vault-endpoint-url "$VAULT_ADDR" \
	--vault-auth-method approle \
	--vault-role-id "$vault_role_id" \
	--vault-mount-path "$VAULT_MOUNT_PATH" \
	--vault-secret-storage-path "$VAULT_SECRET_PATH" &
IAM_VAULT_PID=$!
wait_for_server "IAM API Vault server" "http://127.0.0.1:7077/healthz" "$IAM_VAULT_PID"
./versitygw test -a user -s pass -e http://127.0.0.1:7077 iam
stop_process "$IAM_VAULT_PID"
IAM_VAULT_PID=""

# -----------------------------------------------------------------------------
# Coverage Reports (Go 1.20+ Runtime Coverage)
#
# The IAM servers above were started with GOCOVERDIR=<dir>, which causes Go to
# write raw coverage artifacts into these directories:
#
#   /tmp/iam.covdata
#   /tmp/iam.https.covdata
#   /tmp/iam.vault.covdata
#
# Generate individual HTTP, HTTPS, and Vault coverage reports with:
#
#   go tool covdata percent -i=/tmp/iam.covdata
#   go tool covdata percent -i=/tmp/iam.https.covdata
#   go tool covdata percent -i=/tmp/iam.vault.covdata
#
# Generate a merged IAM coverage report with:
#
#   go tool covdata merge \
#     -i=/tmp/iam.covdata,/tmp/iam.https.covdata,/tmp/iam.vault.covdata \
#     -o /tmp/iam.all.covdata
#
#   go tool covdata percent -i=/tmp/iam.all.covdata
#   go tool covdata textfmt -i=/tmp/iam.all.covdata -o /tmp/iam_profile.txt
#   go tool cover -html=/tmp/iam_profile.txt
# -----------------------------------------------------------------------------
