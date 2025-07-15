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

source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/head_bucket.sh
source ./tests/commands/list_buckets.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_bucket.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_lock_config.sh
source ./tests/util/util_ownership.sh
source ./tests/util/util_public_access_block.sh
source ./tests/util/util_rest.sh
source ./tests/util/util_tags.sh

export RUN_USERS=true

@test "REST - HeadBucket" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - HeadBucket - doesn't exist" {
  run head_bucket_rest "$BUCKET_ONE_NAME"
  assert_failure 1
}

@test "REST - bucket tagging - no tags" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run verify_no_bucket_tags_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - bucket tagging - tags" {
  test_key="testKey"
  test_value="testValue"

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run add_verify_bucket_tags_rest "$BUCKET_ONE_NAME" "$test_key" "$test_value"
  assert_success
}

@test "test_rest_list_buckets" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest
  assert_success
}

@test "REST - get, put bucket ownership controls" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run get_and_check_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerEnforced"
  assert_success

  run put_bucket_ownership_controls_rest "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run get_and_check_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success
}

@test "test_rest_set_get_lock_config" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run check_no_object_lock_config_rest "$BUCKET_ONE_NAME"
  assert_success

  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  # in static bucket config, bucket will still exist
  if ! bucket_exists "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run check_object_lock_config_enabled_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - can set object lock enabled on existing buckets" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1300"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run put_bucket_versioning_rest "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  # this enables object lock without a specific retention policy
  run remove_retention_policy_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - cannot set object lock enabled without content-md5" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1301"
  fi
  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  # in static bucket config, bucket will still exist
  if ! bucket_exists "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  if [ "$DIRECT" == "true" ]; then
    sleep 5
  fi

  # this enables object lock without a specific retention policy
  run put_object_lock_config_without_content_md5 "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - get policy w/o policy" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/959"
  fi

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run get_and_check_no_policy_error "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - put policy" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run setup_user_versitygw_or_direct "$USERNAME_ONE" "$PASSWORD_ONE" "user" "$BUCKET_ONE_NAME"
  assert_success
  log 5 "username: ${lines[1]}"
  log 5 "password: ${lines[2]}"

  sleep 5

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/policy_file.txt" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success

  run put_and_check_policy_rest "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/policy_file.txt" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - create bucket test" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  run create_bucket_rest "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest
  assert_success
}

@test "REST - POST call on root endpoint" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1036"
  fi
  run delete_object_empty_bucket_check_error
  assert_success
}

@test "REST - CreateBucket w/invalid acl" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1379"
  fi
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  envs="ACL=public-reads OBJECT_OWNERSHIP=BucketOwnerPreferred"
  run create_bucket_rest_expect_error "$BUCKET_ONE_NAME" "$envs" "400" "InvalidArgument" ""
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-full-control - non-existent user" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1384"
  fi
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    id="id=$ACL_AWS_CANONICAL_ID"0
  else
    id="$AWS_ACCESS_KEY_ID"a
  fi
  envs="GRANT_FULL_CONTROL=$id OBJECT_OWNERSHIP=BucketOwnerPreferred"
  run create_bucket_rest_expect_error "$BUCKET_ONE_NAME" "$envs" "400" "InvalidArgument" "Invalid id"
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-full-control - no ownership control change" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1387"
  fi
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    id="id=$ACL_AWS_CANONICAL_ID"
  else
    id="$AWS_ACCESS_KEY_ID"
  fi
  envs="GRANT_FULL_CONTROL=$id"
  run create_bucket_rest_expect_error "$BUCKET_ONE_NAME" "$envs" "400" "InvalidBucketAclWithObjectOwnership" "Bucket cannot have ACLs set"
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-full-control - success" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}
  if [ "$DIRECT" == "true" ]; then
    id="id=$user_canonical_id"
  else
    id="$user_canonical_id"
  fi
  envs="GRANT_FULL_CONTROL=$id OBJECT_OWNERSHIP=BucketOwnerPreferred"
  run create_bucket_rest_expect_success "$BUCKET_ONE_NAME" "$envs"
  assert_success

  test_file="test_file"
  run create_test_file "$test_file"
  assert_success

  run put_object_rest_with_user "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/${test_file}-copy"
  assert_success
}