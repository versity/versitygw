#!/usr/bin/env bats

# Copyright 2026 Versity Software
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
source ./tests/drivers/complete_multipart_upload/complete_multipart_upload_rest.sh
source ./tests/drivers/upload_part/upload_part_rest.sh

# tags: curl,multipart,checksum,CreateMultipartUpload,invalid-header,x-amz-checksum-type
@test "REST - multipart w/invalid checksum type" {
  local bucket_name mp_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name mp_file <<< "$output"

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$bucket_name" "$mp_file" "FULL_OBJECTS" "" \
    check_rest_expected_error "400" "InvalidRequest" "Value for x-amz-checksum-type header is invalid"
  assert_success
}

# tags: curl,multipart,checksum,CreateMultipartUpload,invalid-header,x-amz-checksum-algorithm
@test "REST - multipart w/invalid checksum algorithm" {
  local bucket_name mp_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name mp_file <<< "$output"

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$bucket_name" "$mp_file" "" "crc64nvm" \
    check_rest_expected_error "400" "InvalidRequest" "Checksum algorithm provided is unsupported."
  assert_success
}

# tags: curl,multipart,checksum,CreateMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart checksum w/crc64nvme, composite" {
  local bucket_name mp_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name mp_file <<< "$output"

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$bucket_name" "$mp_file" "COMPOSITE" "crc64nvme" \
    check_rest_expected_error "400" "InvalidRequest" "The COMPOSITE checksum type cannot be used with the crc64nvme checksum algorithm."
  assert_success
}

# tags: curl,multipart,checksum,CreateMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart checksum w/sha1, full object" {
  local bucket_name mp_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name mp_file <<< "$output"

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$bucket_name" "$mp_file" "FULL_OBJECT" "sha1" \
    check_rest_expected_error "400" "InvalidRequest" "The FULL_OBJECT checksum type cannot be used with the sha1 checksum algorithm."
  assert_success
}

# tags: curl,multipart,checksum,CreateMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart checksum w/sha256, full object" {
  local bucket_name mp_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name mp_file <<< "$output"

  run create_multipart_upload_rest_with_checksum_type_and_algorithm_error "$bucket_name" "$mp_file" "FULL_OBJECT" "sha256" \
    check_rest_expected_error "400" "InvalidRequest" "The FULL_OBJECT checksum type cannot be used with the sha256 checksum algorithm."
  assert_success
}

# tags: curl,multipart,checksum,CreateMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - lowercase checksum type and algorithm" {
  local bucket_name mp_file

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name mp_file <<< "$output"

  run create_multipart_upload_rest "$bucket_name" "$mp_file" "CHECKSUM_TYPE=full_object CHECKSUM_ALGORITHM=crc64nvme" "parse_upload_id"
  assert_success
}

# tags: curl,multipart,checksum,CreateMultipartUpload,UploadPart,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object checksum type doesn't require UploadPart checksums" {
  local bucket_name large_test_file upload_id

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  large_test_file="$output"

  run setup_bucket_and_large_file_v2 "$bucket_name" "$large_test_file"
  assert_success

  run create_multipart_upload_rest "$bucket_name" "$large_test_file" "CHECKSUM_TYPE=FULL_OBJECT CHECKSUM_ALGORITHM=CRC32" "parse_upload_id"
  assert_success
  upload_id=$output
  log 5 "upload ID: $upload_id"

  run upload_part_rest "$bucket_name" "$large_test_file" "$upload_id" 1 "$TEST_FILE_FOLDER/$large_test_file"
  assert_success
}

# tags: unit,checksum,composite-checksum
@test "sha256 - calculate composite checksum w/null byte" {
  local composite

  run calculate_composite_checksum "sha256" "Gaq9AN6Uxmk7WaTR9TzgDhE8m8bzXrfJWReDyLoZAo8=" "GohMQZ27EDvwB3n2iDx4irfxkTQDyvpDB7NFeTYaXn8="
  assert_success
  composite=$output
  assert_equal "$composite" "/UpzIA5Rft0d6bSkAlmgESdRE3vtDbo8hzAn//6Z5UU="
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - sha256" {
  run test_multipart_upload_with_checksum "COMPOSITE" "SHA256"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - sha1" {
  run test_multipart_upload_with_checksum "COMPOSITE" "SHA1"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - crc32" {
  run test_multipart_upload_with_checksum "COMPOSITE" "CRC32"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - crc32c" {
  run test_multipart_upload_with_checksum "COMPOSITE" "CRC32C"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - crc32" {
  run test_multipart_upload_with_checksum "FULL_OBJECT" "CRC32"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - crc32c" {
  run test_multipart_upload_with_checksum "FULL_OBJECT" "CRC32C"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - crc64nvme" {
  run test_multipart_upload_with_checksum "FULL_OBJECT" "CRC64NVME"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,x-amz-checksum-algorithm
@test "REST - multipart - x-amz-checksum-algorithm is ignored in CompleteMultipartUpload" {
  run test_complete_multipart_upload_unneeded_algorithm_parameter "FULL_OBJECT" "CRC32C"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - incorrect sha256" {
  run test_complete_multipart_upload_incorrect_checksum "COMPOSITE" "SHA256"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - incorrect sha1" {
  run test_complete_multipart_upload_incorrect_checksum "COMPOSITE" "SHA1"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - incorrect crc32" {
  run test_complete_multipart_upload_incorrect_checksum "COMPOSITE" "CRC32"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - incorrect crc32c" {
  run test_complete_multipart_upload_incorrect_checksum "COMPOSITE" "CRC32C"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - incorrect crc32" {
  run test_complete_multipart_upload_incorrect_checksum "FULL_OBJECT" "CRC32"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - incorrect crc32c" {
  run test_complete_multipart_upload_incorrect_checksum "FULL_OBJECT" "CRC32C"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - incorrect crc64nvme" {
  run test_complete_multipart_upload_incorrect_checksum "FULL_OBJECT" "CRC64NVME"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - invalid sha1" {
  run test_complete_multipart_upload_invalid_checksum "COMPOSITE" "SHA1"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - invalid sha256" {
  run test_complete_multipart_upload_invalid_checksum "COMPOSITE" "SHA256"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - invalid crc32" {
  run test_complete_multipart_upload_invalid_checksum "COMPOSITE" "CRC32"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - composite - invalid crc32c" {
  run test_complete_multipart_upload_invalid_checksum "COMPOSITE" "CRC32C"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - invalid crc32" {
  run test_complete_multipart_upload_invalid_checksum "FULL_OBJECT" "CRC32"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - invalid crc32c" {
  run test_complete_multipart_upload_invalid_checksum "FULL_OBJECT" "CRC32C"
  assert_success
}

# tags: curl,multipart,checksum,CompleteMultipartUpload,invalid-header,x-amz-checksum-type,x-amz-checksum-algorithm
@test "REST - multipart - full object - invalid crc64nvme" {
  run test_complete_multipart_upload_invalid_checksum "FULL_OBJECT" "CRC64NVME"
  assert_success
}
