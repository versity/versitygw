#!/usr/bin/env bash

# Copyright 2026 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# Migrate selected legacy objects from bucket-default retention to explicit
# object-level retention. It is a dry run unless --apply is specified.

# Example dry run:
# tools/migrate-object-lock-default-retention.sh \
#   --bucket records \
#   --mode COMPLIANCE \
#   --legacy-retain-until 2027-10-08T18:59:27Z \
#   --endpoint-url http://127.0.0.1:7070 \
#   --report records-retention-dry-run.jsonl

# Example apply:
# tools/migrate-object-lock-default-retention.sh \
#   --bucket records \
#   --mode COMPLIANCE \
#   --legacy-retain-until 2027-10-08T18:59:27Z \
#   --endpoint-url http://127.0.0.1:7070 \
#   --report records-retention-applied.jsonl \
#   --apply

set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  migrate-object-lock-default-retention.sh --bucket BUCKET --mode MODE
      --legacy-retain-until TIMESTAMP [options]

Required:
  --bucket BUCKET             Bucket to migrate.
  --mode MODE                 Retention mode: COMPLIANCE or GOVERNANCE.
  --legacy-retain-until TIME  One shared legacy expiration as an RFC 3339
                              timestamp, not a duration or cutoff. Calculate
                              it as legacy bucket-rule CreatedAt + period.

Options:
  --apply                     Write retention. Without this flag, only report
                              proposed changes.
  --endpoint-url URL          S3 endpoint URL.
  --profile NAME              AWS CLI profile.
  --prefix PREFIX             Restrict the migration to this object-key prefix.
  --report FILE               Write newline-delimited JSON results to FILE.
  -h, --help                  Show this help.

The script lists every object version when bucket versioning is enabled. It
skips delete markers and versions with existing retention. It treats only the
S3 NoSuchObjectLockConfiguration response as "no object retention"; any other
API failure stops the migration.

The mode and expiry preserve the pre-fix enforcement behavior. The expiry is
not exposed by the S3 API: derive it from the legacy server-side bucket
configuration before it is replaced. If it is already expired, the script
reports each eligible object as skipped and never writes retention. Review the
dry-run report before rerunning with --apply.
EOF
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

bucket=
mode=
legacy_retain_until=
apply=false
endpoint_url=
profile=
prefix=
report=

while (($#)); do
	case "$1" in
	--bucket)
		bucket=${2:?missing value for --bucket}
		shift 2
		;;
	--mode)
		mode=${2:?missing value for --mode}
		shift 2
		;;
	--legacy-retain-until)
		legacy_retain_until=${2:?missing value for --legacy-retain-until}
		shift 2
		;;
	--apply)
		apply=true
		shift
		;;
	--endpoint-url)
		endpoint_url=${2:?missing value for --endpoint-url}
		shift 2
		;;
	--profile)
		profile=${2:?missing value for --profile}
		shift 2
		;;
	--prefix)
		prefix=${2:?missing value for --prefix}
		shift 2
		;;
	--report)
		report=${2:?missing value for --report}
		shift 2
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		die "unknown argument: $1"
		;;
	esac
done

[[ -n $bucket ]] || die '--bucket is required'
[[ $mode == COMPLIANCE || $mode == GOVERNANCE ]] || die '--mode must be COMPLIANCE or GOVERNANCE'
[[ -n $legacy_retain_until ]] || die '--legacy-retain-until is required'

for command in aws jq python3; do
	command -v "$command" >/dev/null || die "$command is required"
done

aws_args=()
[[ -n $endpoint_url ]] && aws_args+=(--endpoint-url "$endpoint_url")
[[ -n $profile ]] && aws_args+=(--profile "$profile")

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

parse_timestamp() {
	python3 - "$1" <<'PY'
import sys
from datetime import datetime, timezone

value = sys.argv[1].replace("Z", "+00:00")
parsed = datetime.fromisoformat(value)
if parsed.tzinfo is None:
    raise SystemExit("timestamp must include a timezone")
print(parsed.astimezone(timezone.utc).isoformat())
PY
}

legacy_retain_until=$(parse_timestamp "$legacy_retain_until") ||
	die '--legacy-retain-until must be an RFC 3339 timestamp with a timezone'

is_expired() {
	python3 - "$1" <<'PY'
import sys
from datetime import datetime, timezone

until = datetime.fromisoformat(sys.argv[1]).astimezone(timezone.utc)
raise SystemExit(0 if until <= datetime.now(timezone.utc) else 1)
PY
}

emit() {
	local record=$1
	if [[ -n $report ]]; then
		printf '%s\n' "$record" >>"$report"
	else
		printf '%s\n' "$record"
	fi
}

if ! lock_config=$(aws s3api get-object-lock-configuration --bucket "$bucket" "${aws_args[@]}" --output json); then
	die "could not read Object Lock configuration for bucket $bucket"
fi
if [[ $(jq -r '.ObjectLockConfiguration.ObjectLockEnabled // empty' <<<"$lock_config") != Enabled ]]; then
	die "Object Lock is not enabled for bucket $bucket"
fi

versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" "${aws_args[@]}" --output json)
status=$(jq -r '.Status // empty' <<<"$versioning")

if [[ $status == Enabled ]]; then
	list_args=(list-object-versions --bucket "$bucket")
	[[ -n $prefix ]] && list_args+=(--prefix "$prefix")
	aws s3api "${list_args[@]}" "${aws_args[@]}" --output json >"$tmpdir/objects.json"
	jq -r '.Versions[]? | {key: .Key, version_id: .VersionId, last_modified: .LastModified} | @base64' \
		"$tmpdir/objects.json" >"$tmpdir/versions"
else
	list_args=(list-objects-v2 --bucket "$bucket")
	[[ -n $prefix ]] && list_args+=(--prefix "$prefix")
	aws s3api "${list_args[@]}" "${aws_args[@]}" --output json >"$tmpdir/objects.json"
	jq -r '.Contents[]? | {key: .Key, version_id: null, last_modified: .LastModified} | @base64' \
		"$tmpdir/objects.json" >"$tmpdir/versions"
fi

while IFS= read -r encoded; do
	[[ -n $encoded ]] || continue
	object=$(printf '%s' "$encoded" | base64 --decode 2>/dev/null || printf '%s' "$encoded" | base64 -D)
	key=$(jq -r '.key' <<<"$object")
	version_id=$(jq -r '.version_id // empty' <<<"$object")
	last_modified=$(jq -r '.last_modified' <<<"$object")

	if is_expired "$legacy_retain_until"; then
		emit "$(jq -cn --arg key "$key" --arg version_id "$version_id" --arg last_modified "$last_modified" \
			--arg retain_until "$legacy_retain_until" \
			'{action: "skip", reason: "legacy-retention-expired", key: $key, version_id: $version_id, last_modified: $last_modified, retain_until: $retain_until}')"
		continue
	fi

	get_args=(get-object-retention --bucket "$bucket" --key "$key")
	[[ -n $version_id ]] && get_args+=(--version-id "$version_id")
	if aws s3api "${get_args[@]}" "${aws_args[@]}" --output json >"$tmpdir/retention.json" 2>"$tmpdir/error"; then
		emit "$(jq -cn --arg key "$key" --arg version_id "$version_id" --arg last_modified "$last_modified" \
			'{action: "skip", reason: "existing-retention", key: $key, version_id: $version_id, last_modified: $last_modified}')"
		continue
	fi

	if ! grep -q 'NoSuchObjectLockConfiguration' "$tmpdir/error"; then
		cat "$tmpdir/error" >&2
		die "could not inspect retention for key $(printf '%q' "$key")"
	fi

	record=$(jq -cn --arg key "$key" --arg version_id "$version_id" --arg last_modified "$last_modified" \
		--arg mode "$mode" --arg retain_until "$legacy_retain_until" \
		'{action: "propose", key: $key, version_id: $version_id, last_modified: $last_modified, mode: $mode, retain_until: $retain_until}')

	if [[ $apply == false ]]; then
		emit "$record"
		continue
	fi

	retention=$(jq -cn --arg mode "$mode" --arg until "$legacy_retain_until" \
		'{Mode: $mode, RetainUntilDate: $until}')
	put_args=(put-object-retention --bucket "$bucket" --key "$key" --retention "$retention")
	[[ -n $version_id ]] && put_args+=(--version-id "$version_id")
	aws s3api "${put_args[@]}" "${aws_args[@]}"

	verify_args=(get-object-retention --bucket "$bucket" --key "$key")
	[[ -n $version_id ]] && verify_args+=(--version-id "$version_id")
	aws s3api "${verify_args[@]}" "${aws_args[@]}" --output json >"$tmpdir/retention.json"
	verified_mode=$(jq -r '.Retention.Mode // empty' "$tmpdir/retention.json")
	verified_until=$(jq -r '.Retention.RetainUntilDate // empty' "$tmpdir/retention.json")
	[[ $verified_mode == "$mode" ]] || die "retention verification failed for key $(printf '%q' "$key"): unexpected mode"
	[[ $(parse_timestamp "$verified_until") == "$legacy_retain_until" ]] ||
		die "retention verification failed for key $(printf '%q' "$key"): unexpected retain-until date"

	emit "$(jq -c '.action = "applied"' <<<"$record")"
done <"$tmpdir/versions"
