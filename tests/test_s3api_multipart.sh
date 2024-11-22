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

source ./tests/setup.sh
source ./tests/test_aws_root_inner.sh
source ./tests/util_file.sh
source ./tests/util_multipart.sh
source ./tests/util_tags.sh
source ./tests/commands/get_object.sh
source ./tests/commands/put_object.sh
source ./tests/commands/list_multipart_uploads.sh

# abort-multipart-upload
@test "test_abort_multipart_upload" {
  test_abort_multipart_upload_aws_root
}

# complete-multipart-upload
@test "test_complete_multipart_upload" {
  test_complete_multipart_upload_aws_root
}

# create-multipart-upload
@test "test_create_multipart_upload_properties" {
  test_create_multipart_upload_properties_aws_root
}

@test "test-multipart-upload-from-bucket" {
  local bucket_file="bucket-file"

  run create_test_file "$bucket_file"
  assert_success

  run dd if=/dev/urandom of="$TEST_FILE_FOLDER/$bucket_file" bs=5M count=1
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  run multipart_upload_from_bucket "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER"/"$bucket_file" 4
  assert_success

  run get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file-copy" "$TEST_FILE_FOLDER/$bucket_file-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER"/$bucket_file-copy "$TEST_FILE_FOLDER"/$bucket_file
  assert_success
}

@test "test_multipart_upload_from_bucket_range_too_large" {
  local bucket_file="bucket-file"
  run create_large_file "$bucket_file"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  run multipart_upload_range_too_large "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER"/"$bucket_file"
  assert_success
}

@test "test_multipart_upload_from_bucket_range_valid" {
  local bucket_file="bucket-file"
  run create_large_file "$bucket_file"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  run run_and_verify_multipart_upload_with_valid_range "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER/$bucket_file"
  assert_success
}

# test multi-part upload list parts command
@test "test-multipart-upload-list-parts" {
  test_multipart_upload_list_parts_aws_root
}

# test listing of active uploads
@test "test-multipart-upload-list-uploads" {
  local bucket_file_one="bucket-file-one"
  local bucket_file_two="bucket-file-two"

  if [[ $RECREATE_BUCKETS == false ]]; then
    run abort_all_multipart_uploads "$BUCKET_ONE_NAME"
    assert_success
  fi

  run create_test_files "$bucket_file_one" "$bucket_file_two"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  run create_list_check_multipart_uploads "$BUCKET_ONE_NAME" "$bucket_file_one" "$bucket_file_two"
  assert_success
}

