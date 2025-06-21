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

source ./tests/drivers/params.sh

put_bucket_policy() {
  log 6 "put_bucket_policy '$1' '$2' '$3'"
  record_command "put-bucket-policy" "client:$1"
  if ! check_param_count "put_bucket_policy" "command type, bucket, policy file" 3 $#; then
    return 1
  fi
  local put_policy_result=0
  if [[ $1 == 's3api' ]]; then
    policy=$(send_command aws --no-verify-ssl s3api put-bucket-policy --bucket "$2" --policy "file://$3" 2>&1) || put_policy_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    policy=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setpolicy "$3" "s3://$2" 2>&1) || put_policy_result=$?
  elif [[ $1 == 'mc' ]]; then
    policy=$(send_command mc --insecure anonymous set-json "$3" "$MC_ALIAS/$2" 2>&1) || put_policy_result=$?
  elif [ "$1" == 'rest' ]; then
    put_bucket_policy_rest "$2" "$3" || put_policy_result=$?
    return $put_policy_result
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
  # direct can take some time to take effect
  if [ "$DIRECT" == "true" ]; then
    sleep 10
  fi
  return 0
}

put_bucket_policy_with_user() {
  record_command "put-bucket-policy" "client:s3api"
  if ! check_param_count "put_bucket_policy_with_user" "bucket, policy file, username, password" 4 $#; then
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

put_bucket_policy_rest() {
  if ! check_param_count "put_bucket_policy_rest" "bucket, policy file" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" POLICY_FILE="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_bucket_policy.sh); then
    log 2 "error putting bucket policy: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}
