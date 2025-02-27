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
key="$OBJECT_KEY"
# shellcheck disable=SC2153,SC2154
checksum_type="$CHECKSUM_TYPE"
# shellcheck disable=SC2153
payload="$PAYLOAD"

# use this parameter to check incorrect checksums
# shellcheck disable=SC2153,SC2154
checksum_hash="$CHECKSUM"

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
if [ "$payload" == "" ]; then
  payload_hash="$(sha256sum "$data_file" | awk '{print $1}')"
else
  payload_hash="$payload"
fi

cr_data=("PUT" "/$bucket_name/$key" "" "host:$host")
if [ "$checksum_type" == "sha256" ]; then
  if [ -z "$checksum_hash" ]; then
    checksum_hash="$(sha256sum "$data_file" | awk '{print $1}' | xxd -r -p | base64)"
  fi
  cr_data+=("x-amz-checksum-sha256:$checksum_hash")
elif [ "$checksum_type" == "crc32" ]; then
  if [ -z "$checksum_hash" ]; then
    checksum_hash="$(gzip -c -1 "$data_file" | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
  fi
  cr_data+=("x-amz-checksum-crc32:$checksum_hash")
elif [ "$checksum_type" == "crc64nvme" ]; then
  if [ -z "$checksum_hash" ]; then
    if ! checksum_hash=$(DATA_FILE="$data_file" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_crc64nvme.sh 2>&1); then
      log_rest 2 "error calculating crc64nvme checksum: $checksum_hash"
      exit 1
    fi
  fi
  cr_data+=("x-amz-checksum-crc64nvme:$checksum_hash")
fi
cr_data+=("x-amz-content-sha256:$payload_hash" "x-amz-date:$current_date_time")
build_canonical_request "${cr_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"" -X PUT "$AWS_ENDPOINT_URL/$bucket_name/$key")
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
curl_command+=("${header_fields[@]}")
curl_command+=(-T "$data_file" -o "$OUTPUT_FILE")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
