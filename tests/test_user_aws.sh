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

source ./tests/test_user_common.sh
source ./tests/util/util_setup.sh
source ./tests/util/util_users.sh
source ./tests/commands/get_object.sh
source ./tests/commands/put_object.sh

export RUN_USERS=true

@test "test_admin_user_aws" {
  test_admin_user "aws"
}

@test "test_create_user_already_exists_aws" {
  test_create_user_already_exists "aws"
}

@test "test_delete_user_no_access_key" {
  if delete_user ""; then
    fail "delete user with empty access key succeeded"
  fi
}

@test "test_user_user_aws" {
  test_user_user "aws"
}

@test "test_userplus_operation_aws" {
  test_userplus_operation "aws"
}

@test "test_user_get_object" {
  test_file="test_file"

  run setup_user_versitygw_or_direct "$USERNAME_ONE" "$PASSWORD_ONE" "user" "$BUCKET_ONE_NAME"
  assert_success
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_failure

  run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success
}

@test "test_userplus_get_object" {
  test_file="test_file"

  run setup_user_versitygw_or_direct "$USERNAME_ONE" "$PASSWORD_ONE" "userplus" "$BUCKET_ONE_NAME"
  assert_success
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_failure

  run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success
}

@test "test_user_delete_object" {
  test_file="test_file"

  run setup_user_versitygw_or_direct "$USERNAME_ONE" "$PASSWORD_ONE" "user" "$BUCKET_ONE_NAME"
  assert_success
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_failure

  run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username"
  assert_success

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_success
}

@test "test_admin_put_get_object" {
  test_file="test_file"

  run setup_user_versitygw_or_direct "$USERNAME_ONE" "$PASSWORD_ONE" "admin" "$BUCKET_ONE_NAME"
  assert_success
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_success

  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_success

  run get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_failure
  assert_output -p "NoSuchKey"
}

@test "test_user_create_multipart_upload" {
  test_file="test_file"

  run setup_user_versitygw_or_direct "$USERNAME_TWO" "$PASSWORD_TWO" "user" "$BUCKET_ONE_NAME"
  assert_success
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_multipart_upload_s3api_with_user "$BUCKET_ONE_NAME" "dummy" "$username" "$password"
  assert_failure

  run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username"
  assert_success

  run create_multipart_upload_s3api_with_user "$BUCKET_ONE_NAME" "dummy" "$username" "$password"
  assert_success
}
