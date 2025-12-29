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
source ./tests/drivers/delete_object/delete_object_rest.sh
source ./tests/drivers/put_object/put_object_rest.sh

@test "REST - DeleteBucket - can delete with partial multipart upload" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "avoid bucket deletion in static mode"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run create_multipart_upload_rest "$bucket_name" "test_file" "" ""
  assert_success

  run delete_bucket_rest "$bucket_name"
  assert_success
}

@test "REST - DeleteBucket - file - non-versioning" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "avoid bucket deletion in static mode"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "test_file"
  assert_success

  run delete_bucket_rest_expect_error "$bucket_name" "" "409" "BucketNotEmpty" "is not empty"
  assert_success

  run delete_object_rest "$bucket_name" "test_file"
  assert_success

  run delete_bucket_rest "$bucket_name"
  assert_success
}

@test "REST - DeleteBucket - file - versioning" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "avoid bucket deletion in static mode"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "test_file"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run delete_bucket_rest_expect_error "$bucket_name" "" "409" "BucketNotEmpty" "is not empty"
  assert_success

  run delete_object_rest "$bucket_name" "test_file"
  assert_success

  run delete_bucket_rest_expect_error "$bucket_name" "" "409" "BucketNotEmpty" "is not empty"
  assert_success

  run delete_old_versions_base64 "$bucket_name"
  assert_success

  run delete_bucket_rest "$bucket_name"
  assert_success
}

@test "REST - DeleteBucket - invalid x-amz-expected-bucket-owner" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "avoid bucket deletion in static mode"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    expected_http_code="400"
    expected_error_code="InvalidBucketOwnerAWSAccountID"
    expected_error="value of the expected bucket owner"
  else
    expected_http_code="403"
    expected_error_code="AccessDenied"
    expected_error="Access Denied"
  fi
  run send_rest_go_command_expect_error "$expected_http_code" "$expected_error_code" "$expected_error" "-method" "DELETE" \
    "-bucketName" "$bucket_name" "-signedParams" "x-amz-expected-bucket-owner:a"
  assert_success
}

@test "REST - DeleteBucket - incorrect x-amz-expected-bucket-owner" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "avoid bucket deletion in static mode"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "403" "AccessDenied" "Access Denied" "-method" "DELETE" "-bucketName" "$bucket_name" "-signedParams" "x-amz-expected-bucket-owner:012345678901"
  assert_success
}

@test "REST - DeleteBucket - correct x-amz-expected-bucket-owner" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "avoid bucket deletion in static mode"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run send_rest_go_command "204" "-method" "DELETE" "-bucketName" "$bucket_name" "-signedParams" "x-amz-expected-bucket-owner:$AWS_USER_ID"
  assert_success
}
