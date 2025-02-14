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
source ./tests/util/util_bucket.sh
source ./tests/util/util_file.sh

@test "REST - x-amz-checksum-mode" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test_file"
  run create_test_file "$test_file"
  assert_success

  if ! result=$(DATA_FILE="$TEST_FILE_FOLDER/$test_file" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$test_file" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  return 1
}