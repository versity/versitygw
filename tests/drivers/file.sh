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

source ./tests/drivers/params.sh
source ./tests/drivers/put_bucket_ownership_controls/put_bucket_ownership_controls_rest.sh

setup_bucket_and_file() {
  if ! check_param_count_v2 "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_file_base "$1" "setup_bucket_and_files" "$2"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  return 0
}

setup_bucket_and_file_v2() {
  if ! check_param_count_v2 "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_file_base "$1" "setup_bucket_and_files_v2" "$2"; then
    log 2 "error setting up bucket and files"
    return 1
  fi
  return 0
}

setup_bucket_and_file_base() {
  if ! check_param_count_v2 "bucket, function, file name" 3 $#; then
    return 1
  fi
  if ! "$2" "$1" "$3"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  return 0
}

setup_bucket_and_files() {
  if ! check_param_count_gt "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_files_base "$1" "setup_bucket" "${@:2}"; then
    log 2 "error setting up bucket and files"
    return 1
  fi
  return 0
}

setup_bucket_and_files_v2() {
  if ! check_param_count_gt "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_files_base "$1" "setup_bucket_v2" "${@:2}"; then
    log 2 "error setting up bucket and files"
    return 1
  fi
  return 0
}

setup_bucket_and_files_base() {
  if ! check_param_count_gt "bucket, setup bucket function, file name" 3 $#; then
    return 1
  fi
  if ! "$2" "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! create_test_files "${@:3}"; then
    log 2 "error creating test files"
    return 1
  fi
  return 0
}

setup_bucket_and_large_file_base() {
  if ! check_param_count_v2 "bucket, file name, function" 3 $#; then
    return 1
  fi
  if ! "$3" "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! create_large_file "$2"; then
    log 2 "error creating large file"
    return 1
  fi
  return 0
}

setup_bucket_and_large_file() {
  if ! check_param_count_v2 "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_large_file_base "$1" "$2" "setup_bucket"; then
    log 2 "error setting up bucket and large file"
    return 1
  fi
  return 0
}

setup_bucket_and_large_file_v2() {
  if ! check_param_count_v2 "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_large_file_base "$1" "$2" "setup_bucket_v2"; then
    log 2 "error setting up bucket and large file"
    return 1
  fi
  return 0
}

chunked_upload_trailer_success() {
  if ! check_param_count_v2 "checksum" 1 $#; then
    return 1
  fi
  if ! bucket_name=$(get_bucket_name "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error getting bucket name: $bucket_name"
    return 1
  fi
  if ! setup_bucket "$bucket_name"; then
    log 2 "error setting up bucket"
    return 1
  fi
  test_file="test-file"
  if ! create_test_file "$test_file" 10000; then
    log 2 "error creating test file"
    return 1
  fi
  if ! put_object_chunked_trailer_success "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$1"; then
    log 2 "error performing chunked upload w/trailer"
    return 1
  fi
  if ! download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"; then
    log 2 "error downloading and comparing file"
    return 1
  fi
  return 0
}

get_file_name() {
  if ! get_file_name_with_prefix "test-file"; then
    return 1
  fi
  return 0
}

get_file_name_with_prefix() {
  if ! check_param_count_v2 "prefix" 1 $#; then
    return 1
  fi
  if ! uuid=$(uuidgen 2>&1); then
    log 2 "error getting UUID: $uuid"
    return 1
  fi
  echo "$1-${uuid}"
}
