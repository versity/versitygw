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
source ./tests/drivers/file.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_bucket_acl/get_bucket_acl_rest.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_object.sh
source ./tests/util/util_public_access_block.sh

export RUN_USERS=true

if [ "$SKIP_ACL_TESTING" == "true" ] || [ "$SKIP_USERS_TESTS" == "true" ]; then
  skip "Skipping ACL tests"
  exit 0
fi

@test "REST - get ACL" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_and_check_acl_rest "$bucket_name"
  assert_success
}

@test "REST - put ACL" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  test_file="test_file"
  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$bucket_name" "BucketOwnerPreferred"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run setup_acl "$TEST_FILE_FOLDER/acl-file.txt" "CanonicalUser" "$user_canonical_id" "READ" "$canonical_id"
  assert_success

  run list_objects_with_user_rest_verify_access_denied "$bucket_name" "$username" "$password"
  assert_success

  run put_bucket_acl_rest "$bucket_name" "$TEST_FILE_FOLDER/acl-file.txt"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    sleep 5
  fi

  run list_objects_with_user_rest_verify_success "$bucket_name" "$username" "$password" "$test_file"
  assert_success
}

@test "REST - put public-read canned acl" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  test_file="test_file"
  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$bucket_name" "BucketOwnerPreferred"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run list_objects_with_user_rest_verify_access_denied "$bucket_name" "$username" "$password"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$bucket_name"
    assert_success
  fi
  run put_canned_acl_rest "$bucket_name" "public-read"
  assert_success

  run list_objects_with_user_rest_verify_success "$bucket_name" "$username" "$password" "$test_file"
  assert_success
}

@test "REST - put invalid ACL" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

   run put_bucket_ownership_controls "$bucket_name" "BucketOwnerPreferred"
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
    run allow_public_access "$bucket_name"
    assert_success
  fi
  run put_invalid_acl_rest_verify_failure "$bucket_name" "$TEST_FILE_FOLDER/acl-file.txt"
  assert_success
}

@test "REST - put public-read-write canned acl" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  test_file="test_file"
  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$bucket_name" "BucketOwnerPreferred"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$username" "$password"
  assert_failure

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$bucket_name"
    assert_success
  fi
  run put_canned_acl_rest "$bucket_name" "public-read-write"
  assert_success

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$username" "$password"
  assert_success
}

@test "REST - invalid canned acl" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1367"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  test_file="test_file"
  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$bucket_name" "BucketOwnerPreferred"
  assert_success

  run put_bucket_acl_rest_canned_invalid "$bucket_name" "privatee"
  assert_success
}

@test "REST - FULL_CONTROL permission not returned for owner after CreateBucket with GRANT_READ_ACP" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1407"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run bucket_cleanup_if_bucket_exists "$bucket_name"
  assert_success
  if [ "$DIRECT" == "true" ]; then
    id="id=$user_canonical_id"
  else
    id="$user_canonical_id"
  fi

  envs="GRANT_READ_ACP=$id OBJECT_OWNERSHIP=BucketOwnerPreferred"
  run create_bucket_rest_expect_success "$bucket_name" "$envs"
  assert_success

  run get_bucket_acl_rest "$bucket_name" "" "check_that_acl_xml_does_not_have_owner_permission"
  assert_success
}
