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

source ./tests/test_user_common.sh
source ./tests/util_users.sh
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
  username="$USERNAME_ONE"
  password="$USERNAME_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "user" || fail "error creating user if nonexistent"

  run create_test_file "$test_file"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite not being bucket owner"
  fi
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "failed to add object to bucket"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password" || fail "error getting object"
}

@test "test_userplus_get_object" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "admin" || fail "error creating user if nonexistent"

  run create_test_file "$test_file"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite not being bucket owner"
  fi
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "failed to add object to bucket"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password" || fail "error getting object"
}

@test "test_user_delete_object" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "user" || fail "error creating user if nonexistent"

  run create_test_file "$test_file"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite not being bucket owner"
  fi
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "failed to add object to bucket"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "error deleting object"
}

@test "test_admin_put_get_object" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "admin" || fail "error creating user if nonexistent"

  run create_test_file "$test_file"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "failed to add object to bucket"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password" || fail "error getting object"
  compare_files "$TEST_FILE_FOLDER/$test_file" "$TEST_FILE_FOLDER/$test_file-copy" || fail "files don't match"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "error deleting object"
  if get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"; then
    fail "file not successfully deleted"
  fi
  # shellcheck disable=SC2154
  [[ "$get_object_error" == *"NoSuchKey"* ]] || fail "unexpected error message: $get_object_error"
  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file" "$test_file-copy"
}

@test "test_user_create_multipart_upload" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "user" || fail "error creating user if nonexistent"

  run create_large_file "$test_file"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  create_multipart_upload_with_user "$BUCKET_ONE_NAME" "dummy" "$username" "$password" || fail "unable to create multipart upload"
}
