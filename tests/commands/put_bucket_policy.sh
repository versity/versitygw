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

put_bucket_policy() {
  record_command "put-bucket-policy" "client:$1"
  if [[ $# -ne 3 ]]; then
    log 2 "'put bucket policy' command requires command type, bucket, policy file"
    return 1
  fi
  local put_policy_result=0
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    policy=$(send_command aws --no-verify-ssl s3api put-bucket-policy --bucket "$2" --policy "file://$3" 2>&1) || put_policy_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    policy=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setpolicy "$3" "s3://$2" 2>&1) || put_policy_result=$?
  elif [[ $1 == 'mc' ]]; then
    policy=$(send_command mc --insecure anonymous set-json "$3" "$MC_ALIAS/$2" 2>&1) || put_policy_result=$?
  else
    log 2 "command 'put bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $put_policy_result -ne 0 ]]; then
    put_bucket_policy_error=$policy
    log 2 "error putting policy: $put_bucket_policy_error"
    export put_bucket_policy_error
    return 1
  fi
  return 0
}

put_bucket_policy_with_user() {
  record_command "put-bucket-policy" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "'put bucket policy with user' command requires bucket, policy file, username, password"
    return 1
  fi
  if ! policy=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" send_command aws --no-verify-ssl s3api put-bucket-policy --bucket "$1" --policy "file://$2" 2>&1); then
    log 2 "error putting bucket policy with user $3: $policy"
    put_bucket_policy_error=$policy
    export put_bucket_policy_error
    return 1
  fi
  return 0
}
