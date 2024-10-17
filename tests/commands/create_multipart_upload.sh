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

# initialize a multipart upload
# params:  bucket, key
# return 0 for success, 1 for failure
create_multipart_upload() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -ne 2 ]; then
    log 2 "create multipart upload function must have bucket, key"
    return 1
  fi

  if ! multipart_data=$(send_command aws --no-verify-ssl s3api create-multipart-upload --bucket "$1" --key "$2" 2>&1); then
    log 2 "Error creating multipart upload: $multipart_data"
    return 1
  fi

  if ! upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq -r '.UploadId' 2>&1); then
    log 2 "error parsing upload ID: $upload_id"
    return 1
  fi
  upload_id="${upload_id//\"/}"
  return 0
}

create_multipart_upload_with_user() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -ne 4 ]; then
    log 2 "create multipart upload function must have bucket, key, username, password"
    return 1
  fi

  if ! multipart_data=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" send_command aws --no-verify-ssl s3api create-multipart-upload --bucket "$1" --key "$2" 2>&1); then
    log 2 "Error creating multipart upload: $multipart_data"
    return 1
  fi

  if ! upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq -r '.UploadId' 2>&1); then
    log 2 "error parsing upload ID: $upload_id"
    return 1
  fi
  upload_id="${upload_id//\"/}"
  return 0
}

create_multipart_upload_params() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -ne 8 ]; then
    log 2 "create multipart upload function with params must have bucket, key, content type, metadata, object lock legal hold status, " \
      "object lock mode, object lock retain until date, and tagging"
    return 1
  fi
  local multipart_data
  multipart_data=$(send_command aws --no-verify-ssl s3api create-multipart-upload \
    --bucket "$1" \
    --key "$2" \
    --content-type "$3" \
    --metadata "$4" \
    --object-lock-legal-hold-status "$5" \
    --object-lock-mode "$6" \
    --object-lock-retain-until-date "$7" \
    --tagging "$8" 2>&1) || local create_result=$?
  if [[ $create_result -ne 0 ]]; then
    log 2 "error creating multipart upload with params: $multipart_data"
    return 1
  fi
  upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq '.UploadId')
  upload_id="${upload_id//\"/}"
  return 0
}

create_multipart_upload_custom() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -lt 2 ]; then
    log 2 "create multipart upload custom function must have at least bucket and key"
    return 1
  fi
  local multipart_data
  log 5 "additional create multipart params"
  for i in "$@"; do
    log 5 "$i"
  done
  log 5 "${*:3}"
  log 5 "aws --no-verify-ssl s3api create-multipart-upload --bucket $1 --key $2 ${*:3}"
  multipart_data=$(send_command aws --no-verify-ssl s3api create-multipart-upload --bucket "$1" --key "$2" 2>&1) || local result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error creating custom multipart data command: $multipart_data"
    return 1
  fi
  log 5 "multipart data: $multipart_data"
  upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq '.UploadId')
  upload_id="${upload_id//\"/}"
  log 5 "upload id: $upload_id"
  return 0
}

create_multipart_upload_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'create_multipart_upload_rest' requires bucket name, key"
    return 1
  fi
  result=$(BUCKET_NAME="$1" OBJECT_KEY="$2" CODE_FILE="$TEST_FILE_FOLDER/response_code.txt" OUTPUT_FILE="$TEST_FILE_FOLDER/output.txt" COMMAND_LOG=$COMMAND_LOG ./tests/rest_scripts/create_multipart_upload.sh)
  log 5 "$result"
  log 5 "code: $(cat "$TEST_FILE_FOLDER"/response_code.txt)"
  log 5 "output: $(cat "$TEST_FILE_FOLDER"/output.txt)"
  return 1

  generate_hash_for_payload ""

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="POST
/$1/$2
upload=
host:$aws_endpoint_url_address
x-amz-content-sha256:UNSIGNED-PAYLOAD
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
UNSIGNED-PAYLOAD"

  if ! generate_sts_string "$current_date_time" "$canonical_request"; then
    log 2 "error generating sts string"
    return 1
  fi
  get_signature
  # shellcheck disable=SC2154
  reply=$(send_command curl -ks -w "%{http_code}" -X POST "$header://$aws_endpoint_url_address/$1/$2?upload" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
    -H "x-amz-date: $current_date_time" \
    -o "$TEST_FILE_FOLDER"/create_multipart_upload_error.txt 2>&1)
  if [[ "$reply" != "200" ]]; then
    log 2 "delete object command returned error: $(cat "$TEST_FILE_FOLDER"/create_multipart_upload_error.txt)"
    return 1
  fi
  return 0
}
