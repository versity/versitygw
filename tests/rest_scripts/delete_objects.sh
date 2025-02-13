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

# shellcheck disable=SC2153,SC2154
payload="$PAYLOAD"
# shellcheck disable=SC2153,SC2154
bucket_name="$BUCKET_NAME"
has_content_md5="${HAS_CONTENT_MD5:="true"}"

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
payload_hash="$(echo -n "$payload" | sha256sum | awk '{print $1}')"
if [ "$has_content_md5" == "true" ]; then
  content_md5=$(echo -n "$payload" | openssl dgst -binary -md5 | openssl base64)
fi

canonical_request="POST
/$bucket_name
delete=
"
if [ "$has_content_md5" == "true" ]; then
  canonical_request+="content-md5:$content_md5
"
fi
canonical_request+="host:$host
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

"
if [ "$has_content_md5" == "true" ]; then
  canonical_request+="content-md5;"
fi
canonical_request+="host;x-amz-content-sha256;x-amz-date
$payload_hash"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"" -X POST "$AWS_ENDPOINT_URL/$bucket_name?delete")
signed_headers=""
if [ "$has_content_md5" == "true" ]; then
  signed_headers+="content-md5;"
fi
signed_headers+="host;x-amz-content-sha256;x-amz-date"
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$signed_headers,Signature=$signature\"")
curl_command+=(-H "\"Content-Type: application/xml\"")
if [ "$has_content_md5" == "true" ]; then
  curl_command+=(-H "\"content-md5: $content_md5\"")
fi
curl_command+=(-H "\"x-amz-content-sha256: $payload_hash\""
-H "\"x-amz-date: $current_date_time\"")
curl_command+=(-o "$OUTPUT_FILE")
curl_command+=(-d "\"${payload//\"/\\\"}\"")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
