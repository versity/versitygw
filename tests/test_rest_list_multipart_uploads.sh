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

# tags: curl,ListMultipartUploads,multipart
@test "REST - ListMultipartUploads - Initiator and Owner data shown" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2142"
  fi
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

# tags: curl,ListMultipartUploads,multipart,uploadId,next-key-marker,next-upload-id-marker
@test "REST - ListMultipartUploads - NextKeyMarker and NextUploadIdMarker set to last item" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2144"
  fi
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

  local last_key last_upload_id
  if [[ "$test_file_one" < "$test_file_two" ]]; then
    last_key="$test_file_two"
    last_upload_id="$upload_id_two"
  else
    last_key="$test_file_one"
    last_upload_id="$upload_id_one"
  fi

  run list_multipart_uploads_check_next_values "$bucket_name" "$last_key" "$last_upload_id"
  assert_success
}

# tags: curl,ListMultipartUploads,multipart,uploadId,key-marker
@test "REST - ListMultipartUploads - uploadId and key combo work" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2149"
  fi
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

  local first_key first_upload_id second_key second_upload_id
  if [[ "$test_file_one" < "$test_file_two" ]]; then
    first_key="$test_file_one"
    first_upload_id="$upload_id_one"
    second_key="$test_file_two"
    second_upload_id="$upload_id_two"
  else
    first_key="$test_file_two"
    first_upload_id="$upload_id_two"
    second_key="$test_file_one"
    second_upload_id="$upload_id_one"
  fi

  run list_multipart_uploads_get_check_next_values "$bucket_name" "$second_key" "$second_upload_id" "$first_key" "$first_upload_id"
  assert_success
}

# tags: curl,ListMultipartUploads,multipart,uploadId
@test "REST - ListMultipartUploads - uploadId without key should be ignored" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2150"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_one=$output

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_two=$output

  local first_upload_id second_upload_id
  if [[ "$upload_id_one" < "$upload_id_two" ]]; then
    first_upload_id="$upload_id_one"
    second_upload_id="$upload_id_two"
  else
    first_upload_id="$upload_id_two"
    second_upload_id="$upload_id_one"
  fi

  run list_multipart_uploads_check_no_upload_id_in_response "$bucket_name" "$second_upload_id" "$first_upload_id"
  assert_success
}

# tags: curl,ListMultipartUploads,multipart,prefix,delimiter
@test "REST - ListMultipartUploads - prefix and delimiter" {
  file_names=("a-b-1.txt" "a-b-2.txt" "a-b/c-1.txt" "a-b/c-2.txt" "a-b/d.txt" "a/c.txt")
  local prefix="a-"
  run create_test_files_and_folders "${file_names[@]}"
  assert_success

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  for file_name in "${file_names[@]}"; do
    run create_multipart_upload_rest "$bucket_name" "$file_name" "" ""
    assert_success
  done

  run list_multipart_uploads_rest "$bucket_name"
  assert_success
  log 5 "uploads: $output"

  run list_uploads_with_prefix_and_delimiter_check_results "$bucket_name" "$prefix" "/" "a-b/" "--" "a-b-1.txt" "a-b-2.txt"
  assert_success
}

# tags: curl,ListMultipartUploads,multipart,encoding-type
@test "REST - ListMultipartUploads - encoding type" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2156"
  fi
  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_test_files_with_prefix " "
  assert_success
  base_file_name="$output"
  file_name="${base_file_name}(test)+"
  log 5 "file name: '$file_name'"

  run send_rest_go_command_callback "200" "parse_upload_id" "-method" "POST" "-query" "uploads" "-bucketName" "$bucket_name" "-objectKey" "$file_name"
  assert_success
  upload_id=$output

  run list_multipart_uploads_check_encoding "$bucket_name" "&encoding-type=url" "${base_file_name/ /+}%28test%29%2B"
  assert_success

  run list_multipart_uploads_check_encoding "$bucket_name" "" "$file_name"
  assert_success
}

# tags: curl,ListMultipartUploads,multipart,encoding-type,invalid-query
@test "REST - ListMultipartUploads - invalid encoding type" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2156"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_one=$output

  local invalid_encoding="abc"
  run send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "Invalid Encoding Method specified" \
    "encoding-type" "$invalid_encoding" "-bucketName" "$bucket_name" "-query" "uploads&encoding-type=$invalid_encoding"
  assert_success
}

# tags: curl,ListMultipartUploads,multipart,uploadId,invalid-query
@test "REST - ListMultipartUploads - uploads/uploadId combo" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2155"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name test_file <<< "$output"

  run create_multipart_upload_rest "$bucket_name" "$test_file" "" "parse_upload_id"
  assert_success
  upload_id_one=$output

  run send_rest_go_command_expect_error "400" "InvalidArgument" "Conflicting query string parameters" "-query" "uploads&uploadId=$upload_id_one" "-bucketName" "$bucket_name"
  assert_success
}
