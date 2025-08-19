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
source ./tests/drivers/delete_object/delete_object_rest.sh
source ./tests/drivers/put_object/put_object_rest.sh

@test "REST - DeleteBucket - can delete with partial multipart upload" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_multipart_upload_rest "$BUCKET_ONE_NAME" "test_file" ""
  assert_success

  run delete_bucket_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - DeleteBucket - file - non-versioning" {
  run setup_bucket_and_add_file "$BUCKET_ONE_NAME" "test_file"
  assert_success

  run delete_bucket_rest_expect_error "$BUCKET_ONE_NAME" "" "409" "BucketNotEmpty" "is not empty"
  assert_success

  run delete_object_rest "$BUCKET_ONE_NAME" "test_file"
  assert_success

  run delete_bucket_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - DeleteBucket - file - versioning" {
  run setup_bucket_and_add_file "$BUCKET_ONE_NAME" "test_file"
  assert_success

  run put_bucket_versioning_rest "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run delete_bucket_rest_expect_error "$BUCKET_ONE_NAME" "" "409" "BucketNotEmpty" "is not empty"
  assert_success

  run delete_object_rest "$BUCKET_ONE_NAME" "test_file"
  assert_success

  run delete_bucket_rest_expect_error "$BUCKET_ONE_NAME" "" "409" "BucketNotEmpty" "is not empty"
  assert_success

  run delete_old_versions "$BUCKET_ONE_NAME"
  assert_success

  run delete_bucket_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - DeleteBucket - invalid x-amz-expected-bucket-owner" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1428"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidBucketOwnerAWSAccountID" "value of the expected bucket owner" "-method" "DELETE" "-bucketName" "$BUCKET_ONE_NAME" "-signedParams" "x-amz-expected-bucket-owner:01234567890"
  assert_success
}

@test "REST - DeleteBucket - incorrect x-amz-expected-bucket-owner" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1428"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run send_rest_go_command_expect_error "403" "AccessDenied" "Access Denied" "-method" "DELETE" "-bucketName" "$BUCKET_ONE_NAME" "-signedParams" "x-amz-expected-bucket-owner:012345678901"
  assert_success
}

@test "REST - DeleteBucket - correct x-amz-expected-bucket-owner" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run send_rest_go_command "204" "-method" "DELETE" "-bucketName" "$BUCKET_ONE_NAME" "-signedParams" "x-amz-expected-bucket-owner:$AWS_USER_ID"
  assert_success
}
