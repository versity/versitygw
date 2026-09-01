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

create_website_with_random_string_and_add_permissions() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  local bucket_name="$1"
  local response random_string policy_file

  if ! response=$(create_website_with_random_string "$bucket_name" 2>&1); then
    log 2 "error creating website: $response"
    return 1
  fi
  read -r _ random_string <<< "$response"
  log 5 "random string: $random_string"

  if [ "$DIRECT" == "true" ]; then
    if ! put_public_access_block "$bucket_name" "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" > /dev/null 2>&1; then
      log 2 "error putting public access block"
      return 1
    fi
  fi

  if ! response=$(setup_policy_with_single_statement_v2 "2012-10-17" "Allow" "*" "s3:GetObject" "arn:aws:s3:::$bucket_name/*" 2>&1); then
    log 2 "error setting up policy: $response"
    return 1
  fi
  policy_file="$response"

  if ! put_bucket_policy_rest "$bucket_name" "$TEST_FILE_FOLDER"/"$policy_file"; then
    log 2 "error putting bucket policy"
    return 1
  fi
  printf '%s\n' "$random_string"
  return 0
}
