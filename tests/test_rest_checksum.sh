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

export RUN_USERS=true
test_file="test_file"

@test "REST - invalid checksum type" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_invalid_checksum_type "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - sha256 checksum - invalid" {
  run check_checksum_rest_invalid "sha256"
  assert_success
}

@test "REST - sha256 checksum - incorrect" {
  run check_checksum_rest_incorrect "sha256"
  assert_success
}

@test "REST - sha256 checksum - correct" {
  run add_correct_checksum "sha256"
  assert_success
}

@test "REST - HeadObject returns x-amz-checksum-sha256" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_checksum "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "sha256"
  assert_success

  run check_checksum_rest_sha256 "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "REST - crc32 checksum - invalid" {
  run check_checksum_rest_invalid "crc32c"
  assert_success
}

@test "REST - crc32 checksum - incorrect" {
  run check_checksum_rest_incorrect "crc32"
  assert_success
}

@test "REST - crc32 checksum - correct" {
  run add_correct_checksum "crc32"
  assert_success
}

@test "REST - crc32 checksum - HeadObject" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_checksum "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "crc32"
  assert_success

  run check_checksum_rest_crc32 "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "REST - crc64nvme checksum - invalid" {
  run check_checksum_rest_invalid "crc64nvme"
  assert_success
}

@test "REST - crc64nvme checksum - incorrect" {
  run check_checksum_rest_incorrect "crc64nvme"
  assert_success
}

@test "REST - crc64nvme checksum - correct" {
  run add_correct_checksum "sha256"
  assert_success
}

@test "REST - crc32c checksum - invalid" {
  run check_checksum_rest_invalid "crc32c"
  assert_success
}

@test "REST - crc32c checksum - incorrect" {
  run check_checksum_rest_incorrect "crc32c"
  assert_success
}

@test "REST - crc32c checksum - correct" {
  run add_correct_checksum "crc32c"
  assert_success
}

@test "REST - sha1 checksum - invalid" {
  run check_checksum_rest_invalid "sha1"
  assert_success
}

@test "REST - sha1 checksum - incorrect" {
  run check_checksum_rest_incorrect "sha1"
  assert_success
}

@test "REST - sha1 checksum - correct" {
  run add_correct_checksum "sha1"
  assert_success
}

@test "REST - attempt to get checksum without checksum mode" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run add_correct_checksum "sha256"
  assert_success

  run head_object_without_and_with_checksum "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - HeadObject - default crc64nvme checksum" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_default_checksum "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}
