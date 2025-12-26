#!/usr/bin/env bats

# Copyright 2025 Versity Software
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

put_simple_bucket_policy() {
  if ! check_param_count_v2 "bucket" 1 $#; then
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    user_id="$DIRECT_S3_ROOT_ACCOUNT_NAME"
  else
    user_id="$AWS_ACCESS_KEY_ID"
  fi

  if ! setup_policy_with_single_statement "$TEST_FILE_FOLDER/policy_file" "2012-10-17" "Allow" "$user_id" "s3:*" "arn:aws:s3:::$1"; then
    log 2 "error setting up policy"
    return 1
  fi
  log 5 "policy: $TEST_FILE_FOLDER/policy_file"
  if ! put_bucket_policy_rest "$1" "$TEST_FILE_FOLDER/policy_file"; then
    log 2 "error putting policy"
    return 1
  fi
  return 0
}

put_public_bucket_policy() {
  if ! check_param_count_v2 "bucket" 1 $#; then
    return 1
  fi

  if ! setup_policy_with_single_statement "$TEST_FILE_FOLDER/policy_file" "2012-10-17" "Allow" "*" "s3:*" "arn:aws:s3:::$1"; then
    log 2 "error setting up policy"
    return 1
  fi

  if ! put_bucket_policy_rest "$1" "$TEST_FILE_FOLDER/policy_file"; then
    log 2 "error putting policy"
    return 1
  fi
  return 0
}