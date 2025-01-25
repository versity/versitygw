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

source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_bucket.sh
source ./tests/util/util_chunked_upload.sh
source ./tests/util/util_file.sh

@test "REST - chunked upload, no content length" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test-file"
  run create_test_files "$test_file"
  assert_success

  run attempt_seed_signature_without_content_length "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "test_rest_chunked_upload" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test-file"
  run create_test_files "$test_file"
  assert_success

  if ! result=$(COMMAND_LOG="$COMMAND_LOG" CONTENT_ENCODING="aws-chunked" CONTENT_LENGTH=1000 DECODED_CONTENT_LENGTH=900 BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$test_file" DATA_FILE="$TEST_FILE_FOLDER/$test_file" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object.sh); then
    log 2 "error putting object: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
}