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
acl_file="$ACL_FILE"
# shellcheck disable=SC2153
canned_acl="$CANNED_ACL"

if [ -n "$ACL_FILE" ]; then
  payload="$(cat "$acl_file")"
else
  payload=""
fi

payload_hash="$(echo -n "$payload" | sha256sum | awk '{print $1}')"
current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

canonical_request="PUT
/$bucket_name
acl=
host:$host
"
if [ -n "$CANNED_ACL" ]; then
  canonical_request+="x-amz-acl:$canned_acl
"
fi
canonical_request+="x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

"
canonical_request+="host;"
if [ -n "$CANNED_ACL" ]; then
  canonical_request+="x-amz-acl;"
fi
canonical_request+="x-amz-content-sha256;x-amz-date
$payload_hash"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"" -X PUT "$AWS_ENDPOINT_URL/$bucket_name?acl=")
if [ -n "$CANNED_ACL" ]; then
  acl_header="x-amz-acl;"
else
  acl_header=""
fi
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=host;${acl_header}x-amz-content-sha256;x-amz-date,Signature=$signature\"")
if [ -n "$CANNED_ACL" ]; then
  curl_command+=(-H "\"x-amz-acl: $canned_acl\"")
fi
curl_command+=(-H "\"x-amz-content-sha256: $payload_hash\""
-H "\"x-amz-date: $current_date_time\"")
if [ -n "$ACL_FILE" ]; then
  curl_command+=(-d "\"${payload//\"/\\\"}\"")
fi
curl_command+=(-o "$OUTPUT_FILE")

# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
