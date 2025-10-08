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
source ./tests/drivers/get_bucket_tagging/get_bucket_tagging_rest.sh
source ./tests/drivers/put_bucket_tagging/put_bucket_tagging_rest.sh

@test "REST PutBucketTagging - more than 50 tags" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "BadRequest" "Bucket tag count cannot be greater than 50" \
    "-commandType" "putBucketTagging" "-bucketName" "$bucket_name" "-tagCount" 51 "-contentMD5"
  assert_success
}

@test "REST PutBucketTagging - tag key with control character" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1579"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidTag" "The TagKey you have provided is invalid" \
    "-commandType" "putBucketTagging" "-bucketName" "$bucket_name" "-tagKey" "te\tst" "-tagValue" "value" "-contentMD5"
  assert_success
}

@test "REST PutBucketTagging - duplicate tag key" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidTag" "Cannot provide multiple Tags with the same key" \
    "-commandType" "putBucketTagging" "-bucketName" "$bucket_name" "-tagKey" "test" "-tagValue" "one" \
    "-tagKey" "test" "-tagValue" "two" "-contentMD5"
  assert_success
}

@test "REST PutBucketTagging - tag value with control character" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1579"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidTag" "The TagValue you have provided is invalid" \
    "-commandType" "putBucketTagging" "-bucketName" "$bucket_name" "-tagKey" "test" "-tagValue" "val\tue" "-contentMD5"
  assert_success
}

@test "REST PutBucketTagging - empty tag key" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1583"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run put_bucket_tagging_check_invalid_key_fields "$bucket_name" ""
  assert_success
}

@test "REST PutBucketTagging - returns invalid key" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1583"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run put_bucket_tagging_check_invalid_key_fields "$bucket_name" "te&st"
  assert_success
}

@test "REST - PutBucketTagging - success" {
  test_key="testKey"
  test_value="testValue"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run add_verify_bucket_tags_rest "$bucket_name" "$test_key" "$test_value"
  assert_success
}
