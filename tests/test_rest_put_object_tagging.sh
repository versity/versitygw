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

load ./bats-support/load
load ./bats-assert/load

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_object_tagging/get_object_tagging_rest.sh
source ./tests/drivers/list_object_versions/list_object_versions_rest.sh
source ./tests/drivers/put_object_tagging/put_object_tagging_rest.sh
source ./tests/util/util_public_access_block.sh
source ./tests/setup.sh

test_file="test_file"

@test "REST - PutObjectTagging - content-md5 not required for object tagging" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run put_bucket_object_run_command "$bucket_name" "$test_file" "200" "-commandType" "putObjectTagging" "-tagKey" "key" "-tagValue" "value"
  assert_success

  run get_check_object_tags_single_set_go "$bucket_name" "$test_file" "key" "value"
  assert_success
}

@test "REST - PutObjectTagging - invalid key returns invalid key in error" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1663"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run get_check_tag_error_with_invalid_key "$bucket_name" "$test_file" "ke&y" "value"
  assert_success
}

@test "REST - PutObjectTagging - success with content-md5" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run put_bucket_object_run_command "$bucket_name" "$test_file" "200" "-commandType" "putObjectTagging" "-tagKey" "key" "-tagValue" "value" "-contentMD5"
  assert_success

  run get_check_object_tags_single_set_go "$bucket_name" "$test_file" "key" "value"
  assert_success
}

@test "REST - PutObjectTagging - mismatched bucket owner" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run put_bucket_object_run_command_expect_error "$bucket_name" "$test_file" "403" "AccessDenied" "Access Denied" \
    "-commandType" "putObjectTagging" "-tagKey" "key" "-tagValue" "value" "-contentMD5" "-signedParams" "x-amz-expected-bucket-owner:012345678901"
  assert_success
}

@test "REST -PutObjectTagging - older version" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "cannot change versioning status for static buckets"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_versioning_file_two_versions "$bucket_name" "$test_file"
  assert_success

  run tag_old_version "$bucket_name" "$test_file"
  assert_success
}