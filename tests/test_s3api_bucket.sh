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
source ./tests/util/util_create_bucket.sh
source ./tests/util/util_file.sh
source ./tests/util/util_head_bucket.sh
source ./tests/util/util_lock_config.sh
source ./tests/util/util_object.sh
source ./tests/util/util_tags.sh
source ./tests/util/util_users.sh
source ./tests/test_s3api_root_inner.sh
source ./tests/test_common.sh
source ./tests/test_common_acl.sh
source ./tests/commands/copy_object.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/get_bucket_versioning.sh
source ./tests/commands/get_object.sh
source ./tests/commands/get_object_attributes.sh
source ./tests/commands/get_object_legal_hold.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/get_object_retention.sh
source ./tests/commands/get_object_tagging.sh
source ./tests/commands/list_object_versions.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_policy.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object.sh
source ./tests/commands/put_object_legal_hold.sh
source ./tests/commands/put_object_lock_configuration.sh
source ./tests/commands/put_object_retention.sh
source ./tests/commands/put_public_access_block.sh
source ./tests/commands/select_object_content.sh

export RUN_USERS=true

@test "test_create_bucket_invalid_name" {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  run create_and_check_bucket_invalid_name "s3api"
  assert_success
}

# create-bucket
@test "test_create_delete_bucket_s3api" {
  test_common_create_delete_bucket "s3api"
}

# delete-bucket - test_create_delete_bucket_s3api

# delete-bucket-policy
@test "test_get_put_delete_bucket_policy" {
  if [[ -n $SKIP_POLICY ]]; then
    skip "will not test policy actions with SKIP_POLICY set"
  fi
  test_common_get_put_delete_bucket_policy "s3api"
}


# get-bucket-acl
@test "test_get_bucket_acl" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run get_bucket_acl_and_check_owner "s3api" "$BUCKET_ONE_NAME"
  assert_success
}

# get-bucket-location
@test "test_get_bucket_location" {
  test_common_get_bucket_location "s3api"
}

# get-bucket-policy - test_get_put_delete_bucket_policy

# get-bucket-tagging - test_set_get_delete_bucket_tags

@test "test_head_bucket" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run check_for_empty_region "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_head_bucket_doesnt_exist" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip test for static buckets"
  fi
  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  run bucket_info_without_bucket
  assert_success
}

@test "test_head_bucket_invalid_name" {
  if head_bucket "s3api" ""; then
    fail "able to get bucket info for invalid name"
  fi
}

# test listing buckets on versitygw
@test "test_list_buckets" {
  test_common_list_buckets "s3api"
}

@test "test_put_bucket_acl" {
  test_common_put_bucket_acl "s3api"
}

# delete-bucket-tagging
@test "test-set-get-delete-bucket-tags" {
  test_common_set_get_delete_bucket_tags "s3api"
}
