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
source ./tests/drivers/rest.sh
source ./tests/util/util_file.sh
source ./tests/util/util_list_parts.sh
source ./tests/util/util_setup.sh

test_file="test_file"

@test "REST - multipart upload create then abort" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_abort_multipart_upload_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - multipart upload create, list parts" {
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$test_file" 4
  assert_success

  run upload_check_parts "$BUCKET_ONE_NAME" "$test_file" \
    "$TEST_FILE_FOLDER/$test_file-0" "$TEST_FILE_FOLDER/$test_file-1" "$TEST_FILE_FOLDER/$test_file-2" "$TEST_FILE_FOLDER/$test_file-3"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - complete upload - invalid part" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1008"
  fi
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_upload_finish_wrong_etag "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - upload part copy (UploadPartCopy)" {
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_upload_part_copy_rest "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - UploadPartCopy w/o upload ID" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1226"
  fi
  run upload_part_copy_without_upload_id_or_part_number "$BUCKET_ONE_NAME" "$test_file" "1" "" \
    400 "InvalidArgument" "This operation does not accept partNumber without uploadId"
  assert_success
}

@test "REST - UploadPartCopy w/o part number" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1229"
  fi
  run upload_part_copy_without_upload_id_or_part_number "$BUCKET_ONE_NAME" "$test_file" "" "dummy" \
    405 "MethodNotAllowed" "The specified method is not allowed against this resource"
  assert_success
}

@test "REST - UploadPartCopy - ETag is quoted" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1235"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run upload_part_copy_check_etag_header "$BUCKET_ONE_NAME" "$test_file"-mp "$BUCKET_ONE_NAME/$test_file"
  assert_success
}

@test "REST - UploadPart - ETag is quoted" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1233"
  fi
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$test_file" 4
  assert_success

  run create_multipart_upload_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success
  # shellcheck disable=SC2030
  upload_id=$output

  run upload_part_check_etag_header "$BUCKET_ONE_NAME" "$test_file" "$upload_id"
  assert_success
}

@test "REST - UploadPart w/o part number" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1236"
  fi
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$test_file" 4
  assert_success

  run upload_part_rest_without_part_number "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - UploadPart w/o upload ID" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1237"
  fi
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$test_file" 4
  assert_success

  run upload_part_rest_without_upload_id "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - multipart w/invalid checksum type" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$BUCKET_ONE_NAME" "$test_file" "FULL_OBJECTS" "" \
    check_rest_expected_error "400" "InvalidRequest" "Value for x-amz-checksum-type header is invalid"
  assert_success
}

@test "REST - multipart w/invalid checksum algorithm" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$BUCKET_ONE_NAME" "$test_file" "" "crc64nvm" \
    check_rest_expected_error "400" "InvalidRequest" "Checksum algorithm provided is unsupported."
  assert_success
}

@test "REST - multipart checksum w/crc64nvme, composite" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1329"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$BUCKET_ONE_NAME" "$test_file" "COMPOSITE" "crc64nvme" \
    check_rest_expected_error "400" "InvalidRequest" "The COMPOSITE checksum type cannot be used with the crc64nvme checksum algorithm."
  assert_success
}

@test "REST - multipart checksum w/sha1, full object" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1329"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$BUCKET_ONE_NAME" "$test_file" "FULL_OBJECT" "sha1" \
    check_rest_expected_error "400" "InvalidRequest" "The FULL_OBJECT checksum type cannot be used with the sha1 checksum algorithm."
  assert_success
}

@test "REST - multipart checksum w/sha256, full object" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1329"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$BUCKET_ONE_NAME" "$test_file" "FULL_OBJECT" "sha256" \
    check_rest_expected_error "400" "InvalidRequest" "The FULL_OBJECT checksum type cannot be used with the sha256 checksum algorithm."
  assert_success
}


