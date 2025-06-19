#!/usr/bin/env bash

# Copyright 2024 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

source ./tests/rest_scripts/rest.sh

# Fields

# shellcheck disable=SC2153
bucket_name="$BUCKET_NAME"
# shellcheck disable=SC2153
key="$(echo -n "$OBJECT_KEY" | jq -sRr @uri)"
# shellcheck disable=SC2153
status="$STATUS"
# shellcheck disable=SC2153
omit_payload="${OMIT_PAYLOAD:=false}"
# shellcheck disable=SC2153
version_id="$VERSION_ID"
# shellcheck disable=SC2153
omit_content_md5="${OMIT_CONTENT_MD5:=false}"

if [ "$omit_payload" == "false" ]; then
  payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
   <Status>$status</Status>
</LegalHold>"
else
  payload=""
fi

payload_hash="$(echo -n "$payload" | sha256sum | awk '{print $1}')"
if [ "$omit_content_md5" == "false" ]; then
  content_md5=$(echo -n "$payload" | openssl dgst -binary -md5 | openssl base64)
fi
current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

canonical_request_data=("PUT" "/$bucket_name/$key")
queries="legal-hold="
if [ "$version_id" != "" ]; then
  queries=$(add_parameter "$queries" "versionId=$version_id")
fi
canonical_request_data+=("$queries")
if [ "$omit_content_md5" == "false" ]; then
  canonical_request_data+=("content-md5:$content_md5")
fi
canonical_request_data+=("host:$host")
canonical_request_data+=("x-amz-content-sha256:$payload_hash" "x-amz-date:$current_date_time")
if ! build_canonical_request "${canonical_request_data[@]}"; then
  log_rest 2 "error building request"
  exit 1
fi

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"" -X PUT "\"$AWS_ENDPOINT_URL/$bucket_name/$key?$queries\""
-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
curl_command+=("${header_fields[@]}")
if [ "$omit_payload" == "false" ]; then
  curl_command+=(-d "\"${payload//\"/\\\"}\"")
fi
curl_command+=(-o "$OUTPUT_FILE")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
