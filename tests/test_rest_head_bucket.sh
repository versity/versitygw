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

@test "REST - HeadBucket - mismatched owner" {
  if [ "$DIRECT" != "true" ]; then
      skip "https://github.com/versity/versitygw/issues/1428"
    fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket_rest_expect_error "$BUCKET_ONE_NAME" "EXPECTED_OWNER=012345678901" "403" "Forbidden"
  assert_success
}

@test "REST - HeadBucket - invalid owner" {
  if [ "$DIRECT" != "true" ]; then
      skip "https://github.com/versity/versitygw/issues/1428"
    fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket_rest_expect_error "$BUCKET_ONE_NAME" "EXPECTED_OWNER=01234567890" "400" "Bad Request"
  assert_success
}

@test "REST - HeadBucket - expected owner success" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run head_bucket_rest_expect_success "$BUCKET_ONE_NAME" "EXPECTED_OWNER=$AWS_USER_ID"
  assert_success
}
