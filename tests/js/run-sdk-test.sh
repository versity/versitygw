#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 <bucket>"
  echo
  echo "Required environment variables:"
  echo "  AWS_ACCESS_KEY_ID      Root access key ID"
  echo "  AWS_SECRET_ACCESS_KEY  Root secret access key"
  echo "  AWS_ENDPOINT_URL       Gateway URL (e.g. http://localhost:7070)"
  echo
  echo "Optional environment variables:"
  echo "  AWS_REGION             AWS region (default: us-east-1)"
  exit 1
}

[[ $# -eq 1 ]] || usage

: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"
: "${AWS_ENDPOINT_URL:?AWS_ENDPOINT_URL is required}"

BUCKET="$1"
REGION="${AWS_REGION:-us-east-1}"

if [[ ! -d "${SCRIPT_DIR}/node_modules" ]]; then
  echo "node_modules not found, running npm install..."
  npm install --prefix "${SCRIPT_DIR}"
fi

exec node "${SCRIPT_DIR}/sdk-test.mjs" \
  --endpoint   "$AWS_ENDPOINT_URL" \
  --access-key "$AWS_ACCESS_KEY_ID" \
  --secret-key "$AWS_SECRET_ACCESS_KEY" \
  --bucket     "$BUCKET" \
  --region     "$REGION"
