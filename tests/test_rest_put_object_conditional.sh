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

# tags: curl, PutObject, If-None-Match, not-implemented
@test "REST - PutObject - If-None-Match - no asterisk" {
  local bucket_name test_file

  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command_expect_error "501" "NotImplemented" "not implemented" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "If-None-Match:true"
  assert_success
}

# tags: curl, PutObject, If-None-Match
@test "REST - PutObject - If-None-Match - block copy" {
  local bucket_name test_file

  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command_expect_error "412" "PreconditionFailed" "did not hold" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "If-None-Match:*"
  assert_success
}

# tags: curl, PutObject, If-None-Match
@test "REST - PutObject - If-None-Match - success" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-none-match:*"
  assert_success
}

# tags: curl, PutObject, If-Match
@test "REST - PutObject - If-Match - file doesn't exist on server" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  send_rest_go_command_expect_error "404" "NoSuchKey" "key does not exist" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:abc"
  assert_success
}

# tags: curl, PutObject, If-Match, ETag
@test "REST - PutObject - If-Match - incorrect etag" {
  local bucket_name test_file

  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command_expect_error "412" "PreconditionFailed" "did not hold" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:abc"
  assert_success
}

# tags: curl, PutObject, If-Match, ETag
@test "REST - PutObject - If-Match - correct etag" {
  local bucket_name test_file etag

  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run get_etag_rest "$bucket_name" "$test_file"
  assert_success
  etag=${lines[${#lines[@]}-1]}
  log 5 "etag: $etag"

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-signedParams" "if-match:$etag"
  assert_success
}
