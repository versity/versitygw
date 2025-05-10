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
source ./tests/test_common.sh
source ./tests/test_common_acl.sh
source ./tests/util/util_create_bucket.sh
source ./tests/util/util_object.sh
source ./tests/util/util_users.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/put_bucket_policy.sh

export RUN_S3CMD=true
export RUN_USERS=true

# complete-multipart-upload
@test "test_complete_multipart_upload" {
  test_common_multipart_upload "s3cmd"
}

# copy-object
@test "test_copy_object" {
  test_common_copy_object "s3cmd"
}

# create-bucket
@test "test_create_delete_bucket" {
  test_common_create_delete_bucket "s3cmd"
}

@test "test_create_bucket_invalid_name_s3cmd" {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  run create_bucket_invalid_name "s3cmd"
  assert_success
  assert_output -p "just the bucket name"
}

# delete-bucket - test_create_delete_bucket

# delete-bucket-policy
@test "test_get_put_delete_bucket_policy" {
  if [[ -n $SKIP_POLICY ]]; then
    skip "will not test policy actions with SKIP_POLICY set"
  fi

  test_common_get_put_delete_bucket_policy "s3cmd"
}

# delete-object - test_put_object

# delete-objects - tested with cleanup before or after tests

# get-bucket-acl - test_put_bucket_acl

# get-bucket-location
@test "test_get_bucket_location" {
  test_common_get_bucket_location "s3cmd"
}

# get-bucket-policy - test_get_put_delete_bucket_policy

# get-object
@test "test_put_get_object" {
  test_common_put_get_object "s3cmd"
}

@test "test_put_object_with_data" {
  test_common_put_object_with_data "s3cmd"
}

@test "test_put_object_no_data" {
  test_common_put_object_no_data "s3cmd"
}

@test "test_put_bucket_acl" {
  skip "https://github.com/versity/versitygw/issues/963"
  test_put_bucket_acl_s3cmd
}

@test 's3cmd - can enable public ACLs for bucket' {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1154"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run put_public_access_block_enable_public_acls "$BUCKET_ONE_NAME"
  assert_success
}

# test listing buckets on versitygw
@test "test_list_buckets_s3cmd" {
  test_common_list_buckets "s3cmd"
}

@test "test_list_objects_s3cmd" {
  test_common_list_objects "s3cmd"
}

#@test "test_presigned_url_utf8_chars_s3cmd" {
#  test_common_presigned_url_utf8_chars "s3cmd"
#}

@test "test_get_bucket_info_s3cmd" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket "s3cmd" "$BUCKET_ONE_NAME"
  assert_success
  assert_output -p "s3://$BUCKET_ONE_NAME"
}

@test "test_get_bucket_info_doesnt_exist_s3cmd" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket "s3cmd" "$BUCKET_ONE_NAME"a
  assert_failure 1
}

@test "test_ls_directory_object" {
  test_common_ls_directory_object "s3cmd"
}
