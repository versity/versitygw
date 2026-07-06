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

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/setup.sh

@test "REST - ListParts - invalid part number marker" {
  local bucket_name file_name upload_id invalid_marker="a"
  local -a parts=()

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run split_file "$TEST_FILE_FOLDER/$file_name" 4
  assert_success
  read -r -a parts <<< "$output"

  run create_multipart_upload_rest "$bucket_name" "$file_name" "" "parse_upload_id"
  assert_success
  upload_id=$output

  run upload_part_rest "$bucket_name" "$file_name" "$upload_id" 1 "${parts[0]}"
  assert_success

  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "not an integer or within integer range" \
    "part-number-marker" "$invalid_marker" \
    "-bucketName" "$bucket_name" "-objectKey" "$file_name" "-query" "part-number-marker=$invalid_marker&uploadId=$upload_id"
  assert_success
}

@test "REST - ListParts - part number marker" {
  local bucket_name file_name upload_id
  local -a parts=() sizes=() etags=()

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run create_multipart_upload_rest "$bucket_name" "$file_name" "" "parse_upload_id"
  assert_success
  upload_id=$output

  run split_file "$TEST_FILE_FOLDER/$file_name" 4
  assert_success
  read -r -a parts <<< "$output"

  for ((i=0; i<${#parts[@]}; i++)) do
    run get_file_size "${parts[$i]}"
    assert_success
    sizes+=("$output")

    run upload_part_rest "$bucket_name" "$file_name" "$upload_id" "$((i+1))" "${parts[i]}"
    assert_success
    etags+=("$output")
  done

  run list_parts_check_with_marker_and_max_parts "$bucket_name" "$file_name" "$upload_id" 1 0 1 "${etags[0]}" "${sizes[0]}"
  assert_success

  run list_parts_check_with_marker_and_max_parts "$bucket_name" "$file_name" "$upload_id" 2 1 3 "${etags[1]}" "${sizes[1]}" "${etags[2]}" "${sizes[2]}"
  assert_success

  run list_parts_check_with_marker_and_max_parts "$bucket_name" "$file_name" "$upload_id" 2 3 4 "${etags[3]}" "${sizes[3]}"
  assert_success

  run list_parts_check_with_marker_and_max_parts "$bucket_name" "$file_name" "$upload_id" 1 4 0
  assert_success
}
