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

get_bucket_acl() {
  record_command "get-bucket-acl" "client:$1"
  if [ $# -ne 2 ]; then
    log 2 "bucket ACL command missing command type, bucket name"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]]; then
    acl=$(send_command aws --no-verify-ssl s3api get-bucket-acl --bucket "$2" 2>&1) || exit_code="$?"
  elif [[ $1 == 's3cmd' ]]; then
    acl=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info "s3://$2" 2>&1) || exit_code="$?"
  else
    log 2 "command 'get bucket acl' not implemented for $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "Error getting bucket ACLs: $acl"
    return 1
  fi
  acl=$(echo "$acl" | grep -v "InsecureRequestWarning")
}

get_bucket_acl_with_user() {
  record_command "get-bucket-acl" "client:s3api"
  if [ $# -ne 3 ]; then
    log 2 "'get bucket ACL with user' command requires bucket name, username, password"
    return 1
  fi
  if ! bucket_acl=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" send_command aws --no-verify-ssl s3api get-bucket-acl --bucket "$1" 2>&1); then
    log 2 "error getting bucket ACLs: $bucket_acl"
    return 1
  fi
  return 0
}