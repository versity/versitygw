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
data_file="$DATA_FILE"
# shellcheck disable=SC2153
bucket_name="$BUCKET_NAME"
# shellcheck disable=SC2153
key="$(echo -n "$OBJECT_KEY" | jq -sRr 'split("/") | map(@uri) | join("/")')"
# shellcheck disable=SC2153,SC2154
checksum_type="$CHECKSUM_TYPE"
# shellcheck disable=SC2153
payload="$PAYLOAD"
# shellcheck disable=SC2153
expires="$EXPIRES"
# use this parameter to check incorrect checksums
# shellcheck disable=SC2153,SC2154
checksum_hash="$CHECKSUM"
# shellcheck disable=SC2153,SC2154
fake_signature="$SIGNATURE"
algorithm_parameter="${ALGORITHM_PARAMETER:=false}"

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
data_file_esc="$(echo -n "$data_file" | sed -e 's/[][`"$^{}]/\\&/g')"
log_rest 5 "sha256sum: $(sha256sum "$data_file")"
if [ "$payload" == "" ]; then
  payload_hash="$(sha256sum "$data_file" | awk '{print $1}' | sed 's/\\//g' )"
else
  payload_hash="$payload"
fi

cr_data=("PUT" "/$bucket_name/$key" "")
if [ -n "$expires" ]; then
  cr_data+=("expires:$expires")
fi
cr_data+=("host:$host")
if [ "$algorithm_parameter" != "false" ]; then
  cr_data+=("x-amz-checksum-algorithm:${checksum_type}")
fi
if [ "$checksum_type" != "" ]; then
  if [ "$checksum_hash" == "" ] && ! checksum_hash=$(DATA_FILE="$data_file" CHECKSUM_TYPE="$checksum_type" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log_rest 2 "error calculating checksum hash"
    exit 1
  fi
  cr_data+=("x-amz-checksum-${checksum_type}:$checksum_hash")
fi
cr_data+=("x-amz-content-sha256:$payload_hash" "x-amz-date:$current_date_time")
build_canonical_request "${cr_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

if [ "$fake_signature" != "" ]; then
  signature="$fake_signature"
fi

curl_command+=(curl -ks -w "\"%{http_code}\"" -X PUT "\"$AWS_ENDPOINT_URL/$bucket_name/$key\"")
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
curl_command+=("${header_fields[@]}")
curl_command+=(-T "\"$data_file_esc\"" -o "$OUTPUT_FILE")
# shellcheck disable=SC2154
log_rest 5 "curl command: ${curl_command[*]}"
eval "${curl_command[*]}" 2>&1
