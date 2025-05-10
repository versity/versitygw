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
key="$OBJECT_KEY"
# shellcheck disable=SC2153,SC2034
upload_id="$UPLOAD_ID"
# shellcheck disable=SC2153
parts="$PARTS"
# shellcheck disable=SC2153
checksum_type="$CHECKSUM_TYPE"
# shellcheck disable=SC2153
checksum_algorithm="$CHECKSUM_ALGORITHM"
# shellcheck disable=SC2153
checksum_hash="$CHECKSUM_HASH"
# shellcheck disable=SC2154
algorithm_parameter="${ALGORITHM_PARAMETER:=false}"

payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">$parts</CompleteMultipartUpload>"
payload_hash="$(echo -n "$payload" | sha256sum | awk '{print $1}')"
current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

cr_data=("POST" "/$bucket_name/$key" "uploadId=$upload_id" "host:$host")
log_rest 5 "Algorithm param: $algorithm_parameter"
lowercase_algorithm="$(echo -n "$checksum_algorithm" | tr '[:upper:]' '[:lower:]')"
if [ "$algorithm_parameter" != "false" ]; then
  cr_data+=("x-amz-checksum-algorithm:${checksum_algorithm}")
fi
if [ "$checksum_hash" != "" ]; then
  cr_data+=("x-amz-checksum-${lowercase_algorithm}:$checksum_hash")
fi
if [ "$checksum_type" != "" ]; then
  cr_data+=("x-amz-checksum-type:$checksum_type")
fi
cr_data+=("x-amz-content-sha256:$payload_hash" "x-amz-date:$current_date_time")
build_canonical_request "${cr_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

curl_command+=(curl -iks -w "\"%{http_code}\"" -X POST "$AWS_ENDPOINT_URL/$bucket_name/$key?uploadId=$upload_id"
-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
curl_command+=(-H "\"Content-Type: application/xml\"")
curl_command+=("${header_fields[@]}")
curl_command+=(-d "\"${payload//\"/\\\"}\"")
curl_command+=(-o "$OUTPUT_FILE")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
