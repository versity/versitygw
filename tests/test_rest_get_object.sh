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

source ./tests/commands/get_object.sh
source ./tests/drivers/complete_multipart_upload/complete_multipart_upload_rest.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/setup.sh

# tags: curl,GetObject,HeadObject,range
@test "REST - range download and compare" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_large_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file"
  assert_success

  download_chunk_size="2000000"
  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$download_chunk_size"
  assert_success
}

# tags: curl,PutObject,GetObject,special-chars,encoding
@test "REST - put, get object, encoded name" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  file_name=" \"<>\\^\`{}|+&?%"
  run setup_bucket_and_file_v2 "$bucket_name" "$file_name"
  assert_success

  run put_object_rest_special_chars "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name/$file_name"
  assert_success

  run list_check_single_object "$bucket_name" "$file_name/$file_name"
  assert_success

  run get_object_rest_special_chars "$bucket_name" "$file_name/$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success

  run delete_object_rest "$bucket_name" "$file_name/$file_name"
  assert_success
}

# tags: curl,GetObject,invalid-header,x-amz-content-sha256
@test "REST - GetObject w/invalid payload type" {
  run get_file_name
  assert_success
  test_file="$output"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run get_object_rest_with_invalid_streaming_type "$bucket_name" "$test_file"
  assert_success
}

# tags: curl,GetObject,partNumber,invalid-header
@test "REST - GetObject - part number 2 w/o multipart upload" {
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_expect_error "416" "InvalidPartNumber" "not satisfiable" "-bucketName" "$bucket_name" "-objectKey" "$file_name" "-query" "partNumber=2"
  assert_success
}

# tags: curl,GetObject,partNumber,range,Content-Range
@test "REST - GetObject - part number 1 returns 206, Content-Range header" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2074"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
    assert_success
    read -r bucket_name file_name <<< "$output"

    run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
    assert_success

    run send_rest_go_command_callback "206" "check_for_header_key_and_value" "-bucketName" "$bucket_name" "-objectKey" "$file_name" "-query" "partNumber=1" \
      "--" "Content-Range" "bytes 0-9/10"
    assert_success
}

# tags: curl,GetObject,invalid-header,response-headers
@test "REST - GetObject - response query - invalid response type" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2075"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  local bad_response_query="response-gibberish"
  run send_rest_go_command_expect_error "400" "InvalidArgument" "$bad_response_query is not in the set of overridable response headers" \
    "-bucketName" "$bucket_name" "-objectKey" "$file_name" "-query" "$bad_response_query=dummy"
  assert_success
}

# tags: curl,GetObject,response-cache-control,response-headers
@test "REST - GetObject - response-cache-control" {
  run test_get_object_with_custom_content_header "cache-control" "dummy"
  assert_success
}

# tags: curl,GetObject,response-content-disposition,response-headers
@test "REST - GetObject - response-content-disposition" {
  run test_get_object_with_custom_content_header "content-disposition" "dummy"
  assert_success
}

# tags: curl,GetObject,response-content-encoding,response-headers
@test "REST - GetObject - response-content-encoding" {
  run test_get_object_with_custom_content_header "content-encoding" "dummy"
  assert_success
}

# tags: curl,GetObject,response-content-language,response-headers
@test "REST - GetObject - response-content-language" {
  run test_get_object_with_custom_content_header "content-language" "dummy"
  assert_success
}

# tags: curl,GetObject,response-content-type,response-headers
@test "REST - GetObject - response-content-type" {
  run test_get_object_with_custom_content_header "content-type" "dummy"
  assert_success
}

# tags: curl,GetObject,response-expires,response-headers
@test "REST - GetObject - response-expires" {
  run test_get_object_with_custom_content_header "expires" "dummy+ one"
  assert_success
}

# tags: curl,GetObject,multipart,partNumber
@test "REST - GetObject - partNumber w/multipart" {
  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME" 8
  assert_success
  read -r bucket_name test_file <<< "$output"

  run split_file_irregular "$TEST_FILE_FOLDER/$test_file" 5242880
  assert_success
  read -r part_one part_two <<< "$output"
  log 5 "part one: $part_one, part two: $part_two"

  run perform_multipart_upload_rest_variable_parts "$bucket_name" "$test_file" "$part_one" "$part_two"
  assert_success

  run get_file_size "$part_one"
  assert_success
  part_size="$output"

  run get_file_size "$TEST_FILE_FOLDER/$test_file"
  assert_success
  file_size="$output"

  run send_get_object_with_part_number_validate_response "$bucket_name" "$test_file" "1" "$part_one" "$file_size" "$part_size"
  assert_success

  run send_get_object_with_part_number_validate_response "$bucket_name" "$test_file" "2" "$part_two" "$file_size" "$part_size"
  assert_success
}
