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

source ./tests/report.sh

put_object() {
  log 6 "put_object"
  record_command "put-object" "client:$1"
  if [ $# -ne 4 ]; then
    log 2 "put object command requires command type, source, destination bucket, destination key"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 mv "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure put "$2" "$MC_ALIAS/$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'rest' ]]; then
    put_object_rest "$2" "$3" "$4" || exit_code=$?
  else
    log 2 "'put object' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error putting object into bucket: $error"
    return 1
  fi
  return 0
}

put_object_with_user() {
  record_command "put-object" "client:$1"
  if [ $# -ne 6 ]; then
    log 2 "put object command requires command type, source, destination bucket, destination key, aws ID, aws secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    put_object_error=$(AWS_ACCESS_KEY_ID="$5" AWS_SECRET_ACCESS_KEY="$6" aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  else
    log 2 "'put object with user' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error putting object into bucket: $put_object_error"
    export put_object_error
    return 1
  fi
  return 0
}

put_object_rest() {
  if [ $# -ne 3 ]; then
    log 2 "'put_object_rest' requires local file, bucket name, key"
    return 1
  fi

  generate_hash_for_payload_file "$1"

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="PUT
/$2/$3

host:$aws_endpoint_url_address
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
$payload_hash"

  if ! generate_sts_string "$current_date_time" "$canonical_request"; then
    log 2 "error generating sts string"
    return 1
  fi
  get_signature
  # shellcheck disable=SC2154
  reply=$(curl -ks -w "%{http_code}" -X PUT "$header://$aws_endpoint_url_address/$2/$3" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: $payload_hash" \
    -H "x-amz-date: $current_date_time" \
    -T "$1" -o "$TEST_FILE_FOLDER"/put_object_error.txt 2>&1)
  if [[ "$reply" != "200" ]]; then
    log 2 "put object command returned error: $(cat "$TEST_FILE_FOLDER"/put_object_error.txt)"
    return 1
  fi
  return 0
}
