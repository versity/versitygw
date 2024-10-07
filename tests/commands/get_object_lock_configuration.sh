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

get_object_lock_configuration() {
  record_command "get-object-lock-configuration" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "'get object lock configuration' command missing bucket name"
    return 1
  fi
  if ! lock_config=$(send_command aws --no-verify-ssl s3api get-object-lock-configuration --bucket "$1" 2>&1); then
    log 2 "error obtaining lock config: $lock_config"
    # shellcheck disable=SC2034
    get_object_lock_config_err=$lock_config
    return 1
  fi
  lock_config=$(echo "$lock_config" | grep -v "InsecureRequestWarning")
  return 0
}

get_object_lock_configuration_rest() {
  log 6 "get_object_lock_configuration_rest"
  if [ $# -ne 1 ]; then
    log 2 "'get_object_lock_configuration_rest' requires bucket name"
    return 1
  fi

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="GET
/$1
object-lock=
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
  reply=$(send_command curl -w "%{http_code}" -ks "$header://$aws_endpoint_url_address/$1?object-lock" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
    -H "x-amz-date: $current_date_time" \
    -o "$TEST_FILE_FOLDER/object-lock-config.txt" 2>&1)
  log 5 "reply: $reply"
  if [[ "$reply" != "200" ]]; then
    log 2 "get object command returned error: $(cat "$TEST_FILE_FOLDER/object-lock-config.txt")"
    return 1
  fi
  return 0
}