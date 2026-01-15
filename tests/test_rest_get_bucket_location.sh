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

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_bucket_location/get_bucket_location_rest.sh
source ./tests/setup.sh

@test "REST - GetBucketLocation - no bucket" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "not valid for static mode"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run send_rest_go_command_expect_error "404" "NoSuchBucket" "does not exist" "-bucketName" "$bucket_name" "-query" "location=" "-method" "GET"
  assert_success
}

@test "REST - GetBucketLocation - us-east-1 is returned as null" {
  log 5 "AWS_REGION: $AWS_REGION"
  if [ "$AWS_REGION" != "us-east-1" ]; then
    skip "test only valid for AWS_REGION of 'us-east-1'"
  fi
  run create_bucket_and_run_command "$BUCKET_ONE_NAME" get_check_bucket_location ""
  assert_success
}

@test "REST - GetBucketLocation - success (non us-east-1)" {
  if [ "$AWS_REGION" == "us-east-1" ]; then
    skip "test not valid for us-east-1"
  fi
  run create_bucket_and_run_command "$BUCKET_ONE_NAME" get_check_bucket_location "$AWS_REGION"
  assert_success
}
