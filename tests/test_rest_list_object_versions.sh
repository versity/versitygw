#!/usr/bin/env bats

# Copyright 2025 Versity Software
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
source ./tests/drivers/list_object_versions/list_object_versions_rest.sh
source ./tests/drivers/objects_and_versions.sh
source ./tests/util/util_time.sh

# tags: curl,ListObjectVersions,versions,invalid-query
@test "ListObjectVersions - accidental query of versions on object returns correct error" {
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "There is no such thing as the ?versions sub-resource for a key" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-query" "versions="
  assert_success
}

# tags: curl,ListObjectVersions,versions,versioning,object-lock,retention,x-amz-object-lock-mode,x-amz-object-lock-retain-until-date,content-md5
@test "ListObjectVersions - version changes after deletion w/retention policy" {
  test_file="test_file"

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_lock_configuration_rest "$bucket_name" ""
  assert_success

  run get_time_seconds_in_future 30
  assert_success
  later_date=${output}Z

  run send_rest_go_command "200" \
    "-bucketName" "$bucket_name" "-objectKey" "$test_file" "-payloadFile" "$TEST_FILE_FOLDER/$test_file" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:GOVERNANCE,x-amz-object-lock-retain-until-date:$later_date"
  assert_success

  run list_object_versions_before_and_after_retention_deletion "$bucket_name" "$test_file"
  assert_success
}

@test "ListObjectVersions - invalid encoding" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2169"
  fi
  run objects_versions_invalid_encoding "versions"
  assert_success
}

@test "ListObjectVersions - encoding success" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2169"
  fi
  run objects_versions_encoding_success "versions" "ListVersionsResult" "Version"
  assert_success
}

@test "ListObjectVersions - version ID marker w/o key marker" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2174"
  fi
  run setup_bucket_and_add_files_v3 "$BUCKET_ONE_NAME" "2"
  assert_success
  read -r bucket_name file_one file_two <<< "$output"

  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "A version-id marker cannot be specified without a key marker" \
    "version-id-marker" "null" "-bucketName" "$bucket_name" "-query" "versions&max-keys=1&version-id-marker=null"
  assert_success
}

@test "ListObjectVersions - key-marker set to first key returns proper values" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2178"
  fi
  run setup_bucket_and_add_files_v3 "$BUCKET_ONE_NAME" "2"
  assert_success
  read -r bucket_name file_one file_two <<< "$output"

  local first_file second_file
  if [[ "$file_one" < "$file_two" ]]; then
    first_file="$file_one"
    second_file="$file_two"
  else
    first_file="$file_two"
    second_file="$file_one"
  fi

  run send_rest_go_command_callback "200" "check_page_with_two_different_keys" \
    "-bucketName" "$bucket_name" "-query" "versions&max-keys=1" "--" "" "$first_file" "$first_file"
  assert_success

  run send_rest_go_command_callback "200" "check_page_with_two_different_keys" \
    "-bucketName" "$bucket_name" "-query" "versions&max-keys=1&key-marker=$first_file" "--" "$first_file" "$second_file"
  assert_success
}

@test "ListObjectVersions - same key, different versions" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2178"
  fi
  run setup_bucket_and_add_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_callback "200" "parse_version_ids_with_same_key" \
    "-bucketName" "$bucket_name" "-query" "versions"
  assert_success
  mapfile -t version_ids <<< "$output"

  run send_rest_go_command_callback "200" "check_page_order_of_version_ids_with_same_key" \
    "-bucketName" "$bucket_name" "-query" "versions&max-keys=1" "--" "" "${version_ids[0]}" "${version_ids[0]}"
  assert_success

  run send_rest_go_command_callback "200" "check_page_order_of_version_ids_with_same_key" \
    "-bucketName" "$bucket_name" "-query" "versions&max-keys=1&key-marker=$file_name&version-id-marker=${version_ids[0]}" \
    "--" "${version_ids[0]}" "${version_ids[1]}" "${version_ids[1]}"
  assert_success

  run send_rest_go_command_callback "200" "check_page_order_of_version_ids_with_same_key" \
    "-bucketName" "$bucket_name" "-query" "versions&max-keys=1&key-marker=$file_name&version-id-marker=${version_ids[1]}" \
    "--" "${version_ids[1]}" "${version_ids[2]}"
  assert_success
}

@test "REST - ListObjectVersions - prefix/delimiter" {
  run setup_delimiter_test
  assert_success
  mapfile -t test_info <<< "$output"
  bucket_name="${test_info[0]}"
  prefix="${test_info[1]}"

  run list_object_versions_with_prefix_and_delimiter_check_results "$bucket_name" "$prefix" "/" "a-b/" "--" "a-b-1.txt" "a-b-2.txt"
  assert_success
}
