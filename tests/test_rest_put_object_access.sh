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

source ./tests/setup.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/util/util_public_access_block.sh

export RUN_USERS=true

# tags: user, curl, PutObject
@test "REST - PutObject with user permission - admin user" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip "skipping versity-specific users tests"
  fi
  local bucket_name test_file username password

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_file_and_user_v2 "$bucket_name" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"
  log 5 "username: $username, password: $password"

  run put_object_rest_with_user "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

# tags: user, curl, PutObject
@test "REST - PutObject with no permission - 'user' user" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip "skipping versity-specific users tests"
  fi
  local bucket_name test_file username password

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_file_and_user_v2 "$bucket_name" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_with_user_and_code "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "403"
  assert_success
}

# tags: user, curl, PutObject
@test "REST - PutObject - user permission, bad signature" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip "skipping versitygw-specific users tests"
  fi
  local bucket_name test_file username password

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  test_file="$output"

  run setup_bucket_file_and_user_v2 "$bucket_name" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_user_bad_signature "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

# tags: user, curl, PutObject
@test "REST - PutObject - invalid x-amz-request-payer" {
  local bucket_name test_file username password

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  username=${lines[2]}
  password=${lines[3]}

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_bucket_ownership_controls "$bucket_name" "BucketOwnerPreferred"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$bucket_name"
    assert_success
  fi

  run put_canned_acl_rest "$bucket_name" "public-read-write"
  assert_success

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-awsAccessKeyId" "$username" "-awsSecretAccessKey" "$password" "-signedParams" "x-amz-request-payer:dummy"
  assert_success
}

# tags: curl, PutObject, x-amz-acl, not-implemented
@test "PutObject - x-amz-acl - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "skip for versitygw - see #1904"
  fi
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_bucket_ownership_controls_rest "$bucket_name" "BucketOwnerPreferred"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$bucket_name"
    assert_success
  fi

  run send_rest_go_command_expect_error "501" "NotImplemented" "not implemented" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" "-bucketName" "$bucket_name" \
    "-objectKey" "$test_file" "-signedParams" "x-amz-acl:public-read"
  assert_success
}

# tags: curl, PutObject, x-amz-grant-full-control, not-implemented
@test "PutObject - x-amz-grant-full-control - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "skip for versitygw - see #1904"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-full-control"
  assert_success
}

# tags: curl, PutObject, x-amz-grant-read, not-implemented
@test "PutObject - x-amz-grant-read - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "skip for versitygw - see #1904"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-read"
  assert_success
}
# tags: curl, PutObject, x-amz-grant-read-acp, not-implemented
@test "PutObject - x-amz-grant-read-acp - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "skip for versitygw - see #1904"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-read-acp"
  assert_success
}

# tags: curl, PutObject, x-amz-grant-write-acp, not-implemented
@test "PutObject - x-amz-grant-write-acp - not implemented" {
  if [ "$DIRECT" != "true" ]; then
    skip "skip for versitygw - see #1904"
  fi
  run attempt_put_object_with_specific_acl "x-amz-grant-write-acp"
  assert_success
}
