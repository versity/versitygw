#!/usr/bin/env bats

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

load ./bats-support/load
load ./bats-assert/load

source ./tests/drivers/get_bucket_ownership_controls/get_bucket_ownership_controls_rest.sh
source ./tests/drivers/user.sh
source ./tests/setup.sh

export RUN_USERS=true

@test "REST - DeleteBucketOwnershipControls - lack permission" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip
  fi
  run setup_bucket_and_user_v2 "$BUCKET_ONE_NAME" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  username=${lines[${#lines[@]}-2]}
  password=${lines[${#lines[@]}-1]}
  log 5 "output: $output"
  log 5 "username: $username, password: $password"

  run send_rest_go_command_expect_error "403" "AccessDenied" "Access Denied" "-awsAccessKeyId" "$username" "-awsSecretAccessKey" "$password" \
    "-method" "DELETE" "-bucketName" "$BUCKET_ONE_NAME" "-query" "ownershipControls="
  assert_success
}

@test "REST - DeleteBucketOwnershipControls - invalid username" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  username="invalid with spaces"
  password="dummy"

  run send_rest_go_command_expect_error "403" "InvalidAccessKeyId" "does not exist in our records" "-awsAccessKeyId" "$username" "-awsSecretAccessKey" "$password" \
    "-method" "DELETE" "-bucketName" "$BUCKET_ONE_NAME" "-query" "ownershipControls="
  assert_success
}

@test "REST - DeleteBucketOwnershipControls - success" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run put_bucket_ownership_controls_rest "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run get_bucket_ownership_controls_rest "$BUCKET_ONE_NAME"
  assert_success
  rule=${output[${#output[@]}-1]}
  assert_equal "$rule" "BucketOwnerPreferred"

  run send_rest_go_command "204" "-method" "DELETE" "-bucketName" "$BUCKET_ONE_NAME" "-query" "ownershipControls="
  assert_success

  run get_bucket_ownership_controls_rest "$BUCKET_ONE_NAME"
  assert_success
  rule=${output[${#output[@]}-1]}
  assert_equal "$rule" ""
}

@test "REST - DeleteBucketOwnershipControls - BucketName is reported in error" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1493"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  if ! send_rest_go_command "204" \
    "-method" "DELETE" "-bucketName" "$BUCKET_ONE_NAME" "-query" "ownershipControls="; then
    log 2 "error deleting ownership controls"
    return 1
  fi

  run get_bucket_ownership_controls_check_error_after_deletion "$BUCKET_ONE_NAME"
  assert_success
}
