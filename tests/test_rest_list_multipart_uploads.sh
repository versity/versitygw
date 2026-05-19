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
source ./tests/drivers/list_multipart_uploads/list_multipart_uploads_rest.sh
source ./tests/drivers/file.sh
source ./tests/setup.sh

@test "REST - ListMultipartUploads - prefix and delimiter" {
  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run split_file "$TEST_FILE_FOLDER/$large_test_file" 2
  assert_success
  read -r part_one part_two <<< "$output"
}

@test "REST - ListMultipartUploads - same key, different upload ID" {
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  local upload_id_one upload_id_two
  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_one=$output

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_two=$output

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_three=$output

  run send_rest_go_command "400" "-bucketName" "$bucket_name" "-query" "uploads"
  assert_success
  return 1
}

@test "REST - ListMultipartUploads - Initiator and Owner data shown" {
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id=$output

  local owner_id initiator_id
  if [ "$DIRECT" == "true" ]; then
    owner_id="$AWS_CANONICAL_ID"
    initiator_id="arn:aws:iam::$DIRECT_AWS_USER_ID:user/$DIRECT_S3_ROOT_ACCOUNT_NAME"
  else
    owner_id="$AWS_ACCESS_KEY_ID"
    initiator_id="$AWS_ACCESS_KEY_ID"
  fi

  run list_multipart_uploads_check_user_data "$bucket_name" "$upload_id" "$owner_id" "$initiator_id"
  assert_success
}

@test "REST - ListMultipartUploads - NextKeyMarker and NextUploadIdMarker set to last item" {
  run setup_bucket_and_files_v3 "$BUCKET_ONE_NAME" 2
  assert_success
  read -r bucket_name test_file_one test_file_two <<< "$output"

  local upload_id_one upload_id_two
  run create_multipart_upload_rest "$bucket_name" "$test_file_one" "" "parse_upload_id"
  assert_success
  upload_id_one=$output

  run create_multipart_upload_rest "$bucket_name" "$test_file_two" "" "parse_upload_id"
  assert_success
  upload_id_two=$output


}