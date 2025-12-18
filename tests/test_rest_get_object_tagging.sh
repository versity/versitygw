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

source ./tests/setup.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_object_tagging/get_object_tagging_rest.sh
source ./tests/drivers/put_object/put_object_rest.sh

@test "REST - GetObjectTagging - no tags" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1686"
  fi
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run get_check_object_tags_empty "$bucket_name" "$test_file"
  assert_success
}

@test "REST - GetObjectTagging - older version returns version ID" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1693"
  fi
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_versioning_file_two_versions "$bucket_name" "$test_file"
  assert_success

  run add_version_tags_check_version_id "$bucket_name" "$test_file"
  assert_success
}

@test "REST - GetObjectTagging - invalid version ID error returns version ID" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1698"
  fi
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  run get_object_tagging_invalid_version_id "$bucket_name" "$test_file"
  assert_success
}