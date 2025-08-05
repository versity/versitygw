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

@test "REST - PutBucketAnalyticsConfiguration" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run send_rest_command_expect_error "BUCKET_NAME=$BUCKET_ONE_NAME" "./tests/rest_scripts/put_bucket_analytics_configuration.sh" "400" "something" "something"
  assert_success
}