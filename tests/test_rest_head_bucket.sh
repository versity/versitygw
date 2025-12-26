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

@test "REST - HeadBucket - mismatched owner" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run head_bucket_rest_expect_error "$bucket_name" "EXPECTED_OWNER=012345678901" "403" "Forbidden"
  assert_success
}

@test "REST - HeadBucket - invalid owner" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    http_code=400
    error_code="Bad Request"
  else
    http_code=403
    error_code="Forbidden"
  fi
  run head_bucket_rest_expect_error "$bucket_name" "EXPECTED_OWNER=01234567890" "$http_code" "$error_code"
  assert_success
}

@test "REST - HeadBucket - doesn't exist" {
  run head_bucket_rest "$BUCKET_ONE_NAME-$(uuidgen)"
  assert_failure 1
}

@test "REST - HeadBucket - expected owner success" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run head_bucket_rest_expect_success "$bucket_name" "EXPECTED_OWNER=$AWS_USER_ID"
  assert_success
}
