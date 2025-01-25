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
checksum="$CHECKSUM"
content_encoding="$CONTENT_ENCODING"
content_length="$CONTENT_LENGTH"
decoded_content_length="$DECODED_CONTENT_LENGTH"

build_canonical_request_string() {
  signed_params=""
  canonical_request="PUT
/$bucket_name/$key

"
  if [ "$content_encoding" != "" ]; then
    canonical_request+="content-encoding:$content_encoding
"
    signed_params=$(add_parameter "$signed_params" "content-encoding" ";")
  fi
  if [ "$CONTENT_LENGTH" != "" ]; then
    canonical_request+="content-length:$CONTENT_LENGTH
"
    signed_params=$(add_parameter "$signed_params" "content-length" ";")
  fi
  canonical_request+="host:$host
"
  if [ "$CHECKSUM" != "" ]; then
    canonical_request+="x-amz-checksum-sha256:$checksum_hash
"
    signed_params=$(add_parameter "$signed_params" "x-amz-checksum-sha256" ";")
  fi
  signed_params=$(add_parameter "$signed_params" "host" ";")
  canonical_request+="x-amz-content-sha256:$payload_hash
"
  signed_params=$(add_parameter "$signed_params" "x-amz-content-sha256" ";")
  canonical_request+="x-amz-date:$current_date_time
"
  signed_params=$(add_parameter "$signed_params" "x-amz-date" ";")
  if [ "$DECODED_CONTENT_LENGTH" != "" ]; then
    canonical_request+="x-amz-decoded-content-length:$decoded_content_length
"
    signed_params=$(add_parameter "$signed_params" "x-amz-decoded-content-length" ";")
  fi
  canonical_request+="
$signed_params
$payload_hash"
}

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
if [ "$CONTENT_ENCODING" == "" ]; then
  payload_hash="$(sha256sum "$data_file" | awk '{print $1}')"
else
  payload_hash="STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
fi
checksum_hash="$(echo -n "$payload_hash" | xxd -r -p | base64)"

build_canonical_request_string

echo "$canonical_request" > "canonical_request.txt"

create_canonical_hash_sts_and_signature

echo "$sts_data" > "sts_data.txt"

curl_command+=(curl --max-time 60 -ks -w "\"%{http_code}\"" -X PUT "$AWS_ENDPOINT_URL/$bucket_name/$key")
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$signed_params,Signature=$signature\"")
if [ "$content_encoding" != "" ]; then
  curl_command+=(-H "\"content-encoding: $content_encoding\"")
fi
if [ "$content_length" != "" ]; then
  curl_command+=(-H "\"content-length: $content_length\"")
fi
if [ "$checksum" == "true" ]; then
  curl_command+=(-H "\"x-amz-checksum-sha256: $checksum_hash\"")
fi
curl_command+=(-H "\"x-amz-content-sha256: $payload_hash\"")
curl_command+=(-H "\"x-amz-date: $current_date_time\"")
if [ "$decoded_content_length" != "" ]; then
  curl_command+=(-H "\"x-amz-decoded-content-length: $decoded_content_length\"")
fi
curl_command+=(-T "$data_file" -o "$OUTPUT_FILE")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
curl_response=$?
if [ -n "$COMMAND_LOG" ] && [ "$curl_response" != "0" ]; then
  echo "curl response code: $curl_response" >> "$COMMAND_LOG"
fi