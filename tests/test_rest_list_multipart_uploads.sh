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

@test "REST - ListMultipartUploads - prefix and delimiter" {
  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run split_file "$TEST_FILE_FOLDER/$large_test_file" 2
  assert_success
  read -r part_one part_two <<< "$output"
}

@test "REST - ListMultipartUploads - different key and upload ID" {
  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run split_file "$TEST_FILE_FOLDER/$large_test_file" 2
  assert_success
  read -r part_one part_two <<< "$output"

  local upload_id_one upload_id_two
  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_one=$output

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_two=$output
}