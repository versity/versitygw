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

get_object() {
  log 6 "get_object"
  record_command "get-object" "client:$1"
  if [ $# -ne 4 ]; then
    log 2 "get object command requires command type, bucket, key, destination"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]]; then
    get_object_error=$(aws --no-verify-ssl s3 mv "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    get_object_error=$(aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_object_error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate get "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    get_object_error=$(mc --insecure get "$MC_ALIAS/$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'rest' ]]; then
    get_object_rest "$2" "$3" "$4" || exit_code=$?
  else
    log 2 "'get object' command not implemented for '$1'"
    return 1
  fi
  log 5 "get object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $get_object_error"
    return 1
  fi
  return 0
}

get_object_with_range() {
  record_command "get-object" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "'get object with range' requires bucket, key, range, outfile"
    return 1
  fi
  if ! get_object_error=$(aws --no-verify-ssl s3api get-object --bucket "$1" --key "$2" --range "$3" "$4" 2>&1); then
    log 2 "error getting object with range: $get_object_error"
    return 1
  fi
  return 0
}

get_object_with_user() {
  log 6 "get_object_with_user"
  record_command "get-object" "client:$1"
  if [ $# -ne 6 ]; then
    log 2 "'get object with user' command requires command type, bucket, key, save location, aws ID, aws secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]] || [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    get_object_error=$(AWS_ACCESS_KEY_ID="$5" AWS_SECRET_ACCESS_KEY="$6" aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    log 5 "s3cmd filename: $3"
    get_object_error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate --access_key="$5" --secret_key="$6" get "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    log 5 "save location: $4"
    get_object_error=$(mc --insecure get "$MC_ALIAS/$2/$3" "$4" 2>&1) || exit_code=$?
  else
    log 2 "'get_object_with_user' not implemented for client '$1'"
    return 1
  fi
  log 5 "get object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $get_object_error"
    return 1
  fi
  return 0
}

get_object_rest() {
  log 6 "get_object_rest"
  if [ $# -ne 3 ]; then
    log 2 "'get_object_rest' requires bucket name, object name, output file"
    return 1
  fi

  generate_hash_for_payload ""

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="GET
/$1/$2

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
  reply=$(curl -w "%{http_code}" -ks "$header://$aws_endpoint_url_address/$1/$2" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
    -H "x-amz-date: $current_date_time" \
    -o "$3" 2>&1)
  log 5 "reply: $reply"
  if [[ "$reply" != "200" ]]; then
    log 2 "get object command returned error: $(cat "$3")"
    return 1
  fi
  return 0
}
