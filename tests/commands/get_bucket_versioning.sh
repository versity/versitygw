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

get_bucket_versioning() {
  record_command "get-bucket-versioning" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "get bucket versioning command requires command type, bucket name"
    return 1
  fi
  local get_result=0
  if [[ $1 == 's3api' ]]; then
    versioning=$(aws --no-verify-ssl s3api get-bucket-versioning --bucket "$2" 2>&1) || get_result=$?
  fi
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting bucket versioning: $versioning"
    return 1
  fi
  return 0
}

get_bucket_versioning_rest() {
  log 6 "get_object_rest"
  if [ $# -ne 1 ]; then
    log 2 "'get_bucket_versioning_rest' requires bucket name"
    return 1
  fi

  #generate_hash_for_payload ""

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="GET
/$1
versioning=
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
  if ! reply=$(curl -w "%{http_code}" -ks "$header://$aws_endpoint_url_address/$1?versioning" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
    -H "x-amz-date: $current_date_time" \
    -o "$TEST_FILE_FOLDER/versioning.txt" 2>&1); then
      log 2 "error retrieving curl reply: $reply"
      return 1
  fi
  log 5 "reply: $reply"
  if [[ "$reply" != "200" ]]; then
    log 2 "get object command returned error: $(cat "$TEST_FILE_FOLDER/versioning.txt")"
    return 1
  fi
  return 0
}