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
source ./tests/util/util_head_object.sh
source ./tests/util/util_setup.sh

@test "REST - HeadObject returns x-amz-checksum-sha256" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1070"
  fi
  test_file="test_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_sha256_checksum "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_checksum_rest "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}