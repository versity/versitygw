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

source ./tests/test_user_common.sh

export RUN_S3CMD=true
export RUN_USERS=true

@test "test_admin_user_s3cmd" {
  test_admin_user "s3cmd"
}

@test "test_create_user_already_exists_s3cmd" {
  test_create_user_already_exists "s3cmd"
}

@test "test_user_user_s3cmd" {
  test_user_user "s3cmd"
}

@test "test_userplus_operation_s3cmd" {
  test_userplus_operation "s3cmd"
}
