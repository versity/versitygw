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

source ./tests/commands/put_object.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_acl.sh
source ./tests/util/util_object.sh
source ./tests/util/util_setup.sh

export RUN_USERS=true

if [ "$SKIP_ACL_TESTING" == "true" ]; then
  skip "Skipping ACL tests"
  exit 0
fi

@test "REST - get ACL" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run get_and_check_acl_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - put ACL" {
  test_file="test_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run setup_acl "$TEST_FILE_FOLDER/acl-file.txt" "CanonicalUser" "$user_canonical_id" "READ" "$canonical_id"
  assert_success

  run list_objects_with_user_rest_verify_access_denied "$BUCKET_ONE_NAME" "$username" "$password"
  assert_success

  run put_bucket_acl_rest "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/acl-file.txt"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    sleep 5
  fi

  run list_objects_with_user_rest_verify_success "$BUCKET_ONE_NAME" "$username" "$password" "$test_file"
  assert_success
}

@test "REST - put public-read canned acl" {
  test_file="test_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run list_objects_with_user_rest_verify_access_denied "$BUCKET_ONE_NAME" "$username" "$password"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$BUCKET_ONE_NAME"
    assert_success
  fi
  run put_canned_acl_rest "$BUCKET_ONE_NAME" "public-read"
  assert_success

  run list_objects_with_user_rest_verify_success "$BUCKET_ONE_NAME" "$username" "$password" "$test_file"
  assert_success
}

@test "REST - put invalid ACL" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/986"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

   run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run setup_acl "$TEST_FILE_FOLDER/acl-file.txt" "CanonicalUser" "$user_canonical_id" "READD" "$canonical_id"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$BUCKET_ONE_NAME"
    assert_success
  fi
  run put_invalid_acl_rest_verify_failure "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/acl-file.txt"
  assert_success
}

@test "REST - put public-read-write canned acl" {
  test_file="test_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_failure

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$BUCKET_ONE_NAME"
    assert_success
  fi
  run put_canned_acl_rest "$BUCKET_ONE_NAME" "public-read-write"
  assert_success

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_success
}

@test "REST - invalid canned acl" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1367"
  fi
  test_file="test_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run put_bucket_acl_rest_canned_invalid "$BUCKET_ONE_NAME" "privatee"
  assert_success
}
