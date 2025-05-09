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
source ./tests/util/util_file.sh

# complete-multipart-upload
@test "test_complete_multipart_upload" {
  test_common_multipart_upload "s3"
}

# copy-object
@test "test_copy_object" {
  test_common_copy_object "s3"
}

# create-bucket
@test "test_create_delete_bucket" {
  test_common_create_delete_bucket "s3"
}

# delete-bucket - test_create_delete_bucket

# delete-object - test_put_object

# delete-objects - tested with recursive bucket delete

# get-object
@test "test_copy_get_object" {
  test_common_put_get_object "s3"
}

@test "test_put_object" {
  test_common_put_object_no_data "s3"
}

@test "test_list_buckets" {
  test_common_list_buckets "s3"
}

@test "test_delete_bucket" {
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    skip "will not test bucket deletion in static bucket test config"
  fi

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run delete_bucket "s3" "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_ls_directory_object" {
  test_common_ls_directory_object "s3"
}