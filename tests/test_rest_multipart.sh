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
source ./tests/drivers/complete_multipart_upload/complete_multipart_upload_rest.sh
source ./tests/drivers/list_multipart_uploads/list_multipart_uploads_rest.sh
source ./tests/drivers/put_object/put_object_s3api.sh
source ./tests/drivers/upload_part/upload_part_rest.sh

# tags: curl,multipart,CreateMultipartUpload,AbortMultipartUpload
@test "REST - multipart upload create then abort" {
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name mp_file <<< "$output"

  run create_abort_multipart_upload_rest "$bucket_name" "$mp_file"
  assert_success
}

# tags: curl,multipart,CreateMultipartUpload,UploadPart,ListParts,CompleteMultipartUpload
@test "REST - multipart upload create, list parts" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  large_test_file="$output"

  run setup_bucket_and_large_file_v2 "$bucket_name" "$large_test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$large_test_file" 4
  assert_success
  read -r part_one part_two part_three part_four <<< "$output"
  log 5 "parts: $part_one $part_two $part_three $part_four"

  run upload_check_parts "$bucket_name" "$large_test_file" \
    "$part_one" "$part_two" "$part_three" "$part_four"
  assert_success

  run check_file_integrity "$TEST_FILE_FOLDER/$large_test_file" "$bucket_name" "$large_test_file" "$TEST_FILE_FOLDER/$large_test_file-copy"
  assert_success
}

# tags: curl,multipart,CompleteMultipartUpload,invalid-header,ETag
@test "REST - complete upload - finish with non-existent part" {
  local bucket_name large_test_file

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name large_test_file <<< "$output"

  run create_upload_finish_wrong_etag "$bucket_name" "$large_test_file"
  assert_success
}

# tags: curl,multipart,UploadPartCopy,x-amz-copy-source
@test "REST - upload part copy (UploadPartCopy)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  large_test_file="$output"

  run setup_bucket_and_large_file_v2 "$bucket_name" "$large_test_file"
  assert_success

  run create_upload_part_copy_rest "$bucket_name" "$large_test_file" "$TEST_FILE_FOLDER/$large_test_file"
  assert_success

  run check_file_integrity "$TEST_FILE_FOLDER/$large_test_file" "$bucket_name" "$large_test_file" "$TEST_FILE_FOLDER/$large_test_file-copy"
  assert_success
}

# tags: curl,multipart,UploadPartCopy,partNumber,invalid-query
@test "REST - UploadPartCopy w/o upload ID" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  mp_file=$output

  run upload_part_copy_without_upload_id_or_part_number "$bucket_name" "$mp_file" "1" "" \
    400 "InvalidArgument" "This operation does not accept partNumber without uploadId"
  assert_success
}

# tags: curl,multipart,UploadPartCopy,invalid-query
@test "REST - UploadPartCopy w/o part number" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  mp_file=$output

  run upload_part_copy_without_upload_id_or_part_number "$bucket_name" "$mp_file" "" "dummy" \
    405 "MethodNotAllowed" "The specified method is not allowed against this resource"
  assert_success
}

# tags: curl,multipart,UploadPartCopy,ETag
@test "REST - UploadPartCopy - ETag is quoted" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  mp_file=$output

  run setup_bucket_and_file_v2 "$bucket_name" "$mp_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$mp_file" "$bucket_name" "$mp_file"
  assert_success

  run upload_part_copy_check_etag_header "$bucket_name" "$mp_file"-mp "$bucket_name/$mp_file"
  assert_success
}

# tags: curl,multipart,UploadPart,ETag
@test "REST - UploadPart - ETag is quoted" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  large_test_file=$output

  run setup_bucket_and_large_file_v2 "$bucket_name" "$large_test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$large_test_file" 4
  assert_success
  first_part=$(echo -n "$output" | awk '{print $1}')

  run create_multipart_upload_rest "$bucket_name" "$large_test_file" "" "parse_upload_id"
  assert_success
  # shellcheck disable=SC2030
  upload_id=$output

  run upload_part_check_etag_header "$bucket_name" "$large_test_file" "$upload_id" "1" "$first_part"
  assert_success
}

# tags: curl,multipart,UploadPart,invalid-query
@test "REST - UploadPart w/o part number" {

  skip "versitygw/curl/fasthttp issue"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  mp_file=$output

  run setup_bucket_and_large_file_v2 "$bucket_name" "$mp_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$mp_file" 4
  assert_success

  run upload_part_rest_without_part_number "$bucket_name" "$mp_file"
  assert_success
}

# tags: openssl,multipart,UploadPart,partNumber,uploadId,invalid-query
@test "REST - UploadPart w/o upload ID" {

  skip "versitygw/curl/fasthttp issue"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  mp_file=$output

  run setup_bucket_and_large_file_v2 "$bucket_name" "$mp_file"
  assert_success

  run send_openssl_go_command_expect_error "400" "InvalidArgument" "This operation does not accept partNumber without uploadId" \
    "-method" "PUT" "-bucketName" "$bucket_name" "-objectKey" "$mp_file" "-query" "partNumber=1"
  assert_success
}

# tags: curl,multipart,CompleteMultipartUpload,invalid-header,x-amz-mp-object-size
@test "REST - multipart - x-amz-mp-object-size - invalid string" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_file_name
  assert_success
  large_test_file="$output"

  run setup_bucket_and_large_file_v2 "$bucket_name" "$large_test_file"
  assert_success

  run complete_multipart_upload_invalid_object_size_string "$bucket_name" "$large_test_file" "$TEST_FILE_FOLDER/$large_test_file"
  assert_success
}

@test "REST - multipart - empty upload ID on completion" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2146"
  fi
  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run complete_multipart_upload_empty_upload_id "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/$file_name"
  assert_success
}

@test "REST - multipart overwrite" {
  local bucket_name file_name

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run complete_multipart_upload_overwrite_part "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/$file_name"
  assert_success
}

@test "REST - multipart - InvalidPart error returns correct etag" {
  if [ "$DIRECT" == "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2525"
  fi
  local bucket_name file_name upload_id parts_payload bad_etag first_etag bad_parts_payload

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run multipart_upload_rest_before_completion "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/$file_name" 2
  assert_success
  read -r upload_id parts_payload <<< "$output"

  bad_etag="00000000000000000000000000000000"
  first_etag=${parts_payload#*<ETag>}
  first_etag=${first_etag%%</ETag>*}
  bad_parts_payload=${parts_payload/"<ETag>$first_etag</ETag>"/"<ETag>$bad_etag</ETag>"}

  run complete_multipart_upload_expect_invalid_part_error_callback "$bucket_name" "$file_name" "$upload_id" "$bad_parts_payload" "1" "$bad_etag"
  assert_success
}

@test "REST - multipart failure, then success" {
  local bucket_name file_name upload_id parts_payload first_etag bad_parts_payload

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run multipart_upload_rest_before_completion "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/$file_name" 2
  assert_success
  read -r upload_id parts_payload <<< "$output"

  first_etag=${parts_payload#*<ETag>}
  first_etag=${first_etag%%</ETag>*}
  bad_parts_payload=${parts_payload/"<ETag>$first_etag</ETag>"/"<ETag>00000000000000000000000000000000</ETag>"}

  run complete_multipart_upload_rest "$bucket_name" "$file_name" "$upload_id" "$bad_parts_payload"
  assert_failure

  run complete_multipart_upload_rest "$bucket_name" "$file_name" "$upload_id" "$parts_payload"
  assert_success
}

@test "REST - multipart abort isolation" {
  local bucket_name file_one_name file_two_name key_name upload_id_one upload_id_two parts_payload_two

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_one_name <<< "$output"

  run setup_large_file_v3
  assert_success
  file_two_name="$output"

  run get_file_name
  assert_success
  key_name="$output"

  run multipart_upload_rest_before_completion "$bucket_name" "$key_name" "$TEST_FILE_FOLDER/$file_one_name" 2
  assert_success
  read -r upload_id_one _ <<< "$output"

  run multipart_upload_rest_before_completion "$bucket_name" "$key_name" "$TEST_FILE_FOLDER/$file_two_name" 2
  assert_success
  read -r upload_id_two parts_payload_two <<< "$output"

  run abort_multipart_upload_rest "$bucket_name" "$key_name" "$upload_id_one"
  assert_success

  run complete_multipart_upload_rest "$bucket_name" "$key_name" "$upload_id_two" "$parts_payload_two"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$file_two_name" "$bucket_name" "$key_name" "$TEST_FILE_FOLDER/${file_two_name}-copy"
  assert_success
}

@test "REST - mix UploadPart and UploadPartCopy" {
  local bucket_one_name test_file bucket_two_name part_one_basename etag_one etag_two

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME" 10
  assert_success
  read -r bucket_one_name test_file <<< "$output"

  run setup_bucket_v3 "$BUCKET_TWO_NAME"
  assert_success
  bucket_two_name="$output"

  run split_file "$TEST_FILE_FOLDER/$test_file" 2
  assert_success
  read -r part_one part_two <<< "$output"

  part_one_basename="$(basename "$part_one")"
  run put_object_rest "$part_two" "$bucket_one_name" "$part_one_basename"
  assert_success

  run create_multipart_upload_rest "$bucket_two_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id="$output"

  run upload_part_copy_rest "$bucket_two_name" "$test_file" "$upload_id" 2 "$bucket_one_name/$part_one_basename"
  assert_success
  etag_two="$output"

  run upload_part_rest "$bucket_two_name" "$test_file" "$upload_id" 1 "$part_one"
  assert_success
  etag_one="$output"

  run list_parts_rest "$bucket_two_name" "$test_file" "$upload_id" "list_parts_check_part_ordering" "--" "$bucket_two_name" "$test_file" "$upload_id" \
    "1" "$etag_one" "2" "$etag_two"
  assert_success

  parts_payload="<Part><ETag>$etag_one</ETag><PartNumber>1</PartNumber></Part><Part><ETag>$etag_two</ETag><PartNumber>2</PartNumber></Part>"
  run complete_multipart_upload_rest "$bucket_two_name" "$test_file" "$upload_id" "$parts_payload"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_two_name" "$test_file" "$TEST_FILE_FOLDER/${test_file}-copy"
  assert_success
}
