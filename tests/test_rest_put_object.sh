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

# tags: curl, PutObject, chunked, x-amz-content-sha256, content-length
@test "REST - put object w/STREAMING-AWS4-HMAC-SHA256-PAYLOAD without content length" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_object_rest_chunked_payload_type_without_content_length "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

# tags: curl, PutObject, content-encoding
@test "REST - PutObject - aws-chunked kept when the payload is not chunked" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_object_rest_with_content_encoding "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "aws-chunked"
  assert_success

  run check_content_encoding "$bucket_name" "$test_file" "aws-chunked"
  assert_success
}

# tags: curl, PutObject, content-encoding, x-amz-content-sha256, invalid-header
@test "REST - PutObject - aws-chunked with UNSIGNED-PAYLOAD rejected" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_object_rest_unsigned_payload_with_aws_chunked "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

# tags: curl, PutObject, Expires, invalid-header
@test "REST - PutObject - invalid 'Expires' parameter" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_object_rest_check_expires_header "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success
}

# tags: curl, PutObject, content-length, invalid-header
@test "REST - put object, missing Content-Length" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1321"
  fi
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_object_without_content_length "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

# tags: curl, PutObject, x-amz-checksum-algorithm, checksum
@test "REST - PutObject w/x-amz-checksum-algorithm" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run put_object_rest_with_unneeded_algorithm_param "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "crc32c"
  assert_success
}

# tags: curl, PutObject
@test "PutObject - metadata keys are made lowercase" {
  local uppercase_key="CAPITAL" uppercase_value="DUMMY" bucket_name test_file

  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
      "-signedParams" "x-amz-meta-$uppercase_key:$uppercase_value"
  assert_success

  run check_metadata_key_case "$bucket_name" "$test_file" "$uppercase_key" "$uppercase_value"
  assert_success
}

# tags: curl, PutObject, Expect
@test "REST - PutObject - expect continue - success" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-method" "PUT" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
        "-signedParams" "Expect:100-continue"
  assert_success
}

# tags: curl, PutObject, Content-Disposition
@test "REST - PutObject - content disposition" {
  local bucket_name test_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run send_rest_go_command "200" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "Content-Disposition:dummy"
  assert_success

  run head_object_check_header_key_and_value "$bucket_name" "$test_file" "Content-Disposition" "dummy"
  assert_success
}

# tags: openssl, PutObject
@test "REST - PutObject - openssl go non-file payload" {
  local bucket_name test_file payload_content

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run bash -c "tr -dc 'a-zA-Z0-9 ' < /dev/urandom | head -c 100"
  assert_success
  payload_content=$output

  run bash -c "echo -n \"$payload_content\" > $TEST_FILE_FOLDER/$test_file"
  assert_success

  run send_openssl_go_command "200" "-method" "PUT" "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payload" "$payload_content"
  assert_success

  run check_file_integrity "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/${test_file}_downloaded"
  assert_success
}
