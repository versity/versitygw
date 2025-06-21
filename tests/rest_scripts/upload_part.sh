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

# shellcheck disable=SC2153
bucket_name="$BUCKET_NAME"
# shellcheck disable=SC2153
key="$OBJECT_KEY"
# shellcheck disable=SC2153
part_number="$PART_NUMBER"
# shellcheck disable=SC2153
upload_id="$UPLOAD_ID"
# shellcheck disable=SC2153
data=$DATA_FILE
# shellcheck disable=SC2153
checksum_type="$CHECKSUM_TYPE"
# shellcheck disable=SC2153
checksum_hash="$CHECKSUM_HASH"

if [ "$data" != "" ]; then
  payload_hash="$(sha256sum "$data" | awk '{print $1}')"
else
  payload_hash="$(echo -n "" | sha256sum | awk '{print $1}')"
fi

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
# shellcheck disable=SC2034
header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
# shellcheck disable=SC2154
cr_data=("PUT" "/$bucket_name/$key")
query_params=""
if [ "$part_number" != "" ]; then
  query_params=$(add_parameter "$query_params" "partNumber=$part_number")
fi
if [ "$upload_id" != "" ]; then
  query_params=$(add_parameter "$query_params" "uploadId=$upload_id")
fi
cr_data+=("$query_params")
cr_data+=("host:$host")
if [ "$checksum_type" != "" ]; then
  if [ "$checksum_hash" == "" ] && ! checksum_hash=$(DATA_FILE="$data" CHECKSUM_TYPE="$checksum_type" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log_rest 2 "error calculating checksum hash: $checksum_hash"
    exit 1
  fi
  cr_data+=("x-amz-checksum-${checksum_type}:$checksum_hash")
fi
cr_data+=("x-amz-content-sha256:$payload_hash" "x-amz-date:$current_date_time")
build_canonical_request "${cr_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

url="'$AWS_ENDPOINT_URL/$bucket_name/$key"
if [ "$query_params" != "" ]; then
  url+="?$query_params"
fi
url+="'"
curl_command+=(curl -isk -w "\"%{http_code}\"" -X PUT "$url"
-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
if [ "$data" == "" ]; then
  curl_command+=(-H "\"Content-Length: 0\"")
fi
curl_command+=("${header_fields[@]}")
curl_command+=(-o "$OUTPUT_FILE")
if [ "$data" != "" ]; then
  curl_command+=(-T "$data")
fi
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
