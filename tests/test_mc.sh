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

source ./tests/test_common.sh
source ./tests/setup.sh
source ./tests/util/util_create_bucket.sh
source ./tests/util/util_head_bucket.sh
source ./tests/util/util_tags.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/put_bucket_policy.sh

export RUN_MC=true

# complete-multipart-upload
@test "test_multipart_upload_mc" {
  test_common_multipart_upload "mc"
}

# copy-object
@test "test_copy_object" {
  test_common_copy_object "mc"
}

# create-bucket
@test "test_create_delete_bucket" {
  test_common_create_delete_bucket "mc"
}

# delete-bucket
@test "test_delete_bucket" {
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    skip "will not test bucket deletion in static bucket test config"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run delete_bucket "mc" "$BUCKET_ONE_NAME"
  assert_success
}

# delete-bucket-policy
@test "test_get_put_delete_bucket_policy" {
  if [[ -n $SKIP_POLICY ]]; then
    skip "will not test policy actions with SKIP_POLICY set"
  fi
  test_common_get_put_delete_bucket_policy "mc"
}

# delete-bucket-tagging
@test "test_set_get_delete_bucket_tags" {
  test_common_set_get_delete_bucket_tags "mc"
}

# delete-object - put-object tests

# delete-object-tagging
@test "test_delete_object_tagging" {
  test_common_delete_object_tagging "mc"
}

# delete-objects - test setup/teardown

# get-bucket-location
@test "test_get_bucket_location" {
  test_common_get_bucket_location "mc"
}

# get-bucket-policy - test_get_put_delete_bucket_policy

# get-bucket-tagging
@test "test_set_get_object_tags_mc" {
  test_common_set_get_object_tags "mc"
}

# get-object
@test "test_put_get_object" {
  test_common_put_get_object "mc"
}

@test "test_put_object-with-data-mc" {
  test_common_put_object_with_data "mc"
}

@test "test_put_object-no-data-mc" {
  test_common_put_object_no_data "mc"
}

@test "test_list_buckets_mc" {
  test_common_list_buckets "mc"
}

@test "test_list_objects_mc" {
  test_common_list_objects "mc"
}


@test "test_presigned_url_utf8_chars_mc" {
  test_common_presigned_url_utf8_chars "mc"
}

@test "test_create_bucket_invalid_name_mc" {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  run create_and_check_bucket_invalid_name "mc"
  assert_success
}

@test "test_get_bucket_info_mc" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run bucket_info_contains_bucket "mc" "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_get_bucket_info_doesnt_exist_mc" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket "mc" "$BUCKET_ONE_NAME"a
  assert_failure 1
}

@test "test_ls_directory_object" {
  test_common_ls_directory_object "mc"
}
