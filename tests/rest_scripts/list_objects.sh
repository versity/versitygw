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
version_two="${VERSION_TWO:-FALSE}"
max_keys="${MAX_KEYS:-0}"
# shellcheck disable=SC2153
if [ "$CONTINUATION_TOKEN" != "" ]; then
  continuation_token=$(jq -rn --arg token "$CONTINUATION_TOKEN" '$token | @uri')
fi

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

#x-amz-object-attributes:ETag
canonical_request="GET
/$bucket_name
"

if [ "$CONTINUATION_TOKEN" != "" ]; then
  add_parameter "canonical_request" "continuation-token=$continuation_token"
fi
if [ "$version_two" != "FALSE" ]; then
  add_parameter "canonical_request" "list-type=2"
fi
if [ "$max_keys" -ne 0 ]; then
  add_parameter "canonical_request" "max-keys=$max_keys"
fi
first_param_added="false"

canonical_request+="
host:$host
x-amz-content-sha256:UNSIGNED-PAYLOAD
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
UNSIGNED-PAYLOAD"
create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"")
url="'$AWS_ENDPOINT_URL/$bucket_name"
if [ "$CONTINUATION_TOKEN" != "" ]; then
  add_parameter "url" "continuation-token=$continuation_token"
fi
if [ "$version_two" != "FALSE" ]; then
  add_parameter "url" "list-type=2"
fi
if [ "$max_keys" -ne 0 ]; then
  add_parameter "url" "max-keys=$max_keys"
fi
first_param_added="false"
url+="'"
curl_command+=("$url")
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature\""
-H "\"x-amz-content-sha256: UNSIGNED-PAYLOAD\""
-H "\"x-amz-date: $current_date_time\""
-o "$OUTPUT_FILE")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
