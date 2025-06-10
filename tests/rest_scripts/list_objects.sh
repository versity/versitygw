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
marker="$MARKER"
# shellcheck disable=SC2153
if [ "$CONTINUATION_TOKEN" != "" ]; then
  continuation_token=$(jq -rn --arg token "$CONTINUATION_TOKEN" '$token | @uri')
fi

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

canonical_request_data=("GET" "/$bucket_name")
queries=""
if [ "$MARKER" != "" ]; then
  queries=$(add_parameter "$queries" "marker=$marker")
fi
if [ "$CONTINUATION_TOKEN" != "" ]; then
  queries=$(add_parameter "$queries" "continuation-token=$continuation_token")
fi
if [ "$version_two" != "FALSE" ]; then
  queries=$(add_parameter "$queries" "list-type=2")
fi
if [ "$max_keys" -ne 0 ]; then
  queries=$(add_parameter "$queries" "max-keys=$max_keys")
fi
canonical_request_data+=("$queries" "host:$host")
canonical_request_data+=("x-amz-content-sha256:UNSIGNED-PAYLOAD" "x-amz-date:$current_date_time")
if ! build_canonical_request "${canonical_request_data[@]}"; then
  log_rest 2 "error building request"
  exit 1
fi

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature
log_rest 5 "cr data: $canonical_request"

curl_command+=(curl -ks -w "\"%{http_code}\"")
url="'$AWS_ENDPOINT_URL/$bucket_name"
if [ "$queries" != "" ]; then
  url+="?$queries"
fi
url+="'"
curl_command+=("$url")
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature\"")
curl_command+=("${header_fields[@]}")
curl_command+=(-o "$OUTPUT_FILE")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
