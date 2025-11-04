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
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_bucket_ownership_controls/get_bucket_ownership_controls_rest.sh
source ./tests/drivers/get_bucket_tagging/get_bucket_tagging_rest.sh
source ./tests/drivers/list_buckets/list_buckets_rest.sh
source ./tests/drivers/put_bucket_tagging/put_bucket_tagging_rest.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_bucket.sh
source ./tests/util/util_delete_object.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_lock_config.sh
source ./tests/util/util_public_access_block.sh
source ./tests/util/util_rest.sh

export RUN_USERS=true

@test "REST - HeadBucket" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run head_bucket_rest "$bucket_name"
  assert_success
}

@test "REST - bucket tagging - no tags" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run verify_no_bucket_tags_rest "$bucket_name"
  assert_success
}

@test "REST - get, put bucket ownership controls" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_and_check_ownership_controls "$bucket_name" "BucketOwnerEnforced"
  assert_success

  run put_bucket_ownership_controls_rest "$bucket_name" "BucketOwnerPreferred"
  assert_success

  run get_and_check_ownership_controls "$bucket_name" "BucketOwnerPreferred"
  assert_success
}

@test "test_rest_set_get_lock_config" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "test not valid for static buckets"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run check_no_object_lock_config_rest "$bucket_name"
  assert_success

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_two_name="$output"

  run setup_bucket_object_lock_enabled_v2 "$bucket_two_name"
  assert_success

  run check_object_lock_config_enabled_rest "$bucket_two_name"
  assert_success
}

@test "REST - can set object lock enabled on existing buckets" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1300"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  # this enables object lock without a specific retention policy
  run remove_retention_policy_rest "$bucket_name"
  assert_success
}

@test "REST - cannot set object lock enabled without content-md5" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1301"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_object_lock_enabled_v2 "$bucket_name"
  assert_success

  # this enables object lock without a specific retention policy
  run put_object_lock_config_without_content_md5 "$bucket_name"
  assert_success
}

@test "REST - get policy w/o policy" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/959"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_and_check_no_policy_error "$bucket_name"
  assert_success
}

@test "REST - put policy" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run setup_user_versitygw_or_direct "$USERNAME_ONE" "$PASSWORD_ONE" "user" "$bucket_name"
  assert_success
  log 5 "username: ${lines[1]}"
  log 5 "password: ${lines[2]}"

  sleep 5

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/policy_file.txt" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$bucket_name"
  assert_success

  run put_and_check_policy_rest "$bucket_name" "$TEST_FILE_FOLDER/policy_file.txt" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$bucket_name"
  assert_success
}

@test "REST - POST call on root endpoint" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1487"
  fi
  run delete_object_empty_bucket_check_error
  assert_success
}

@test "REST - PutBucketTagging - no payload" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1521"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "Missing required header" "-bucketName" "$bucket_name" "-query" "tagging=" "-method" "PUT"
  assert_success
}

@test "REST - PutBucketTagging - invalid Content-MD5" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidDigest" "you specified" "-bucketName" "$bucket_name" "-query" "tagging=" "-method" "PUT" "-signedParams" "Content-MD5:dummy" \
    "-payload" "<Tagging xmlms=\\\"http://s3.amazonaws.com/doc/2006-03-01/\\\"><TagSet><Tag><Key>key</Key><Value>value</Value></Tag></TagSet></Tagging>"
  assert_success
}

@test "REST - PutBucketTagging - invalid Content-MD5 - invalid Content-MD5 itself returned" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1526"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run send_put_bucket_tagging_command_check_invalid_content_md5 "$bucket_name"
  assert_success
}

@test "REST - PutBucketTagging - incorrect Content-MD5" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1525"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "BadDigest" "did not match" "-bucketName" "$bucket_name" "-query" "tagging=" "-method" "PUT" "-incorrectContentMD5" \
    "-payload" "<Tagging xmlms=\\\"http://s3.amazonaws.com/doc/2006-03-01/\\\"><TagSet><Tag><Key>key</Key><Value>value</Value></Tag></TagSet></Tagging>"
  assert_success
}
