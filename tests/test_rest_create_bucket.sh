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

source ./tests/commands/list_buckets.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/list_buckets/list_buckets_rest.sh
source ./tests/setup.sh

export RUN_USERS=true

@test "REST - create bucket test" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run list_check_buckets_rest "$bucket_name"
  assert_success
}

@test "REST - CreateBucket w/invalid acl" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1379"
  fi
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run bucket_cleanup_if_bucket_exists_v2 "$BUCKET_ONE_NAME"
  assert_success

  envs="ACL=public-reads OBJECT_OWNERSHIP=BucketOwnerPreferred"
  run create_bucket_rest_expect_error "$bucket_name" "$envs" "400" "InvalidArgument" ""
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
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  run bucket_cleanup_if_bucket_exists_v2 "$BUCKET_ONE_NAME"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    id="id=$ACL_AWS_CANONICAL_ID"
  else
    id="$AWS_ACCESS_KEY_ID"
  fi
  envs="GRANT_FULL_CONTROL=$id"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_bucket_rest_expect_error "$bucket_name" "$envs" "400" "InvalidBucketAclWithObjectOwnership" "Bucket cannot have ACLs set"
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-full-control - success w/tests" {
  run setup_and_create_bucket_and_check_acl "GRANT_FULL_CONTROL"
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-read" {
  run setup_and_create_bucket_and_check_acl "GRANT_READ"
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-write" {
  run setup_and_create_bucket_and_check_acl "GRANT_WRITE"
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-read-acp" {
  run setup_and_create_bucket_and_check_acl "GRANT_READ_ACP"
  assert_success
}

@test "REST - CreateBucket - x-amz-grant-write-acp" {
  run setup_and_create_bucket_and_check_acl "GRANT_WRITE_ACP"
  assert_success
}
