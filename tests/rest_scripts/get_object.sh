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
key="$(echo -n "$OBJECT_KEY" | jq -sRr 'split("/") | map(@uri) | join("/")')"
# shellcheck disable=SC2153
checksum_mode="${CHECKSUM_MODE:=false}"
# shellcheck disable=SC2153
range="$RANGE"
# shellcheck disable=SC2153
payload="${PAYLOAD:=UNSIGNED-PAYLOAD}"

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

#x-amz-object-attributes:ETag
canonical_request_data+=("GET" "/$bucket_name/$key" "" "host:$host")
if [ "$range" != "" ]; then
  canonical_request_data+=("range:$range")
fi
if [ "$checksum_mode" == "true" ]; then
  canonical_request_data+=("x-amz-checksum-mode:ENABLED")
fi
canonical_request_data+=("x-amz-content-sha256:$payload" "x-amz-date:$current_date_time")

build_canonical_request "${canonical_request_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

output_file_esc="$(echo -n "$OUTPUT_FILE" | sed -e 's/[][`"$^]/\\&/g')"
curl_command+=(curl -ks -w "\"%{http_code}\"" "\"$AWS_ENDPOINT_URL/$bucket_name/$key\""
-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
curl_command+=("${header_fields[@]}")
curl_command+=(-o "\"$output_file_esc\"")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1