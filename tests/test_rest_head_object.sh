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
source ./tests/drivers/get_object_attributes/get_object_attributes_rest.sh
source ./tests/drivers/string.sh

# tags: curl,HeadObject,GetObjectAttributes,ETag,x-amz-object-attributes
@test "REST - head object" {
  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run get_etag_rest "$bucket_name" "$file_name"
  assert_success
  expected_etag=$output

  run check_etag_attribute_rest "$bucket_name" "$file_name" "$expected_etag"
  assert_success
}

# tags: curl,HeadObject,Content-Type
@test "REST - HeadObject - default Content-Type is binary/octet-stream" {
  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run head_object_check_header_key_and_value "$bucket_name" "$file_name" "Content-Type" "binary/octet-stream"
  assert_success
}

@test "REST - HeadObject - letter partNumber" {
  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run send_rest_go_command "400" "-method" "HEAD" "-query" "partNumber=abc" "-objectKey" "$file_name" "-bucketName" "$bucket_name"
  assert_success
}

@test "REST - HeadObject - invalid partNumber" {
  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run send_rest_go_command "416" "-method" "HEAD" "-query" "partNumber=2" "-objectKey" "$file_name" "-bucketName" "$bucket_name"
  assert_success
}

@test "REST - HeadObject - valid partNumbers" {
  file_mb=8
  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME" "$file_mb"
  assert_success
  read -r bucket_name test_file <<< "$output"
  file_bytes=$((file_mb*1024*1024))

  run split_file_irregular "$TEST_FILE_FOLDER/$test_file" 5242880
  assert_success
  read -r part_one part_two <<< "$output"
  log 5 "part one: $part_one, part two: $part_two"

  run perform_multipart_upload_rest_variable_parts "$bucket_name" "$test_file" "$part_one" "$part_two"
  assert_success

  run get_file_size "$part_one"
  assert_success
  part_size_one="$output"

  run get_file_size "$part_one"
  assert_success
  part_size_two="$output"

  run send_rest_go_command_callback "206" "check_header_partial_content_response" "-bucketName" "$bucket_name" "-objectKey" "$test_file" \
    "-method" "HEAD" "-query" "partNumber=1" "--" "1" "$file_bytes" "$part_size_one"
  assert_success

  run send_rest_go_command_callback "206" "check_header_partial_content_response" "-bucketName" "$bucket_name" "-objectKey" "$test_file" \
    "-method" "HEAD" "-query" "partNumber=2" "--" "2" "$file_bytes" "$part_size_two"
  assert_success
}

@test "REST - HeadObject - invalid request header type" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2075"
  fi
  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run send_rest_go_command "400" "-bucketName" "$bucket_name" "-objectKey" "$file_name" \
    "-method" "HEAD" "-query" "response-invalid=invalid"
  assert_success
}

@test "REST - HeadObject - response queries" {
  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  query_suffixes=("cache-control" "content-disposition" "content-encoding" "content-language" "content-type" "expires")

  for suffix in "${query_suffixes[@]}"; do
    run generate_random_string 20 40
    assert_success
    value=$output
    log 5 "value: $value"

    run send_rest_go_command_callback "200" "check_for_header_key_and_value" "-bucketName" "$bucket_name" "-objectKey" "$file_name" \
      "-method" "HEAD" "-query" "response-$suffix=$value" "--" "$suffix" "$value"
    assert_success
  done
}
