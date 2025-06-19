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

source ./tests/logger.sh
source ./tests/commands/get_object.sh

# create a test file and export folder.  do so in temp folder
# params:  filenames
# fail if error
create_test_files() {
  log 6 "create_test_files"
  if [ $# -lt 1 ]; then
    log 2 "'create_test_files' requires file names"
    return 1
  fi
  for name in "$@"; do
    if ! create_test_file "$name"; then
      log 2 "error creating test file"
      return 1
    fi
  done
  return 0
}

# params:  filename, size (optional, defaults to 10)
create_test_file() {
  if [[ ( $# -lt 1 ) || ( $# -gt 2 ) ]]; then
    log 2 "'create_test_file' requires filename, size (optional)"
    return 1
  fi
  if [[ -e "$TEST_FILE_FOLDER/$1" ]]; then
    if ! error=$(rm "$TEST_FILE_FOLDER/$1" 2>&1); then
      log 2 "error removing existing file: $error"
      return 1
    fi
  fi
  if ! error=$(touch "$TEST_FILE_FOLDER/$1" 2>&1); then
    log 2 "error creating new file: $error"
    return 1
  fi
  if [ -z "$2" ]; then
    file_size=10
  else
    file_size="$2"
  fi
  if [ "$file_size" -eq 0 ]; then
    return 0
  fi
  if ! error=$(dd if=/dev/urandom of="$TEST_FILE_FOLDER/$1" bs=1 count="$file_size" 2>&1); then
    log 2 "error adding data to file: $error"
    return 1
  fi
  return 0
}

create_file_single_char() {
  if [ "$#" -ne 3 ]; then
    log 2 "'create_file_single_char' requires filename, size, char"
    return 1
  fi
  if [[ -e "$TEST_FILE_FOLDER/$1" ]]; then
    if ! error=$(rm "$TEST_FILE_FOLDER/$1" 2>&1); then
      log 2 "error removing existing file: $error"
      return 1
    fi
  fi
  if ! error=$(touch "$TEST_FILE_FOLDER/$1" 2>&1); then
    log 2 "error creating new file: $error"
    return 1
  fi
  if ! error=$(dd if=/dev/zero bs=1 count="$2" | tr '\0' "$3" > "$TEST_FILE_FOLDER/$1" 2>&1); then
    log 2 "error adding data to file: $error"
    return 1
  fi
  return 0
}

# params:  folder name
# fail if error
create_test_folder() {
  if [ $# -lt 1 ]; then
    log 2 "'create_test_folder' requires folder names"
    return 1
  fi
  for name in "$@"; do
    if ! error=$(mkdir -p "$TEST_FILE_FOLDER"/"$name" 2>&1); then
      log 2 "error creating folder $name: $error"
      return 1
    fi
  done
  return 0
}

# delete a test file
# params:  filename
# return:  0 for success, 1 for error
delete_test_files() {
  if [ $# -lt 1 ]; then
    log 2 "delete test files command missing filenames"
    return 1
  fi
  if [ -z "$TEST_FILE_FOLDER" ]; then
    log 2 "no test file folder defined, not deleting"
    return 1
  fi
  for name in "$@"; do
    rm -rf "${TEST_FILE_FOLDER:?}"/"${name:?}" || rm_result=$?
    if [[ $rm_result -ne 0 ]]; then
      log 2 "error deleting file $name"
    fi
  done
  return 0
}

get_file_size() {
  if [ $# -ne 1 ]; then
    log 2 "'get_file_size' requires file location"
    return 1
  fi
  local file_size=""
  if [[ "$OSTYPE" == "darwin"* ]]; then
    if ! file_size=$(stat -f %z "$1" 2>&1); then
      log 2 "error getting file size: $file_size"
      return 1
    fi
  else
    if ! file_size=$(stat -c %s "$1" 2>&1); then
      log 2 "error getting file size: $file_size"
      return 1
    fi
  fi
  echo "$file_size"
}

# split file into pieces to test multipart upload
# param: file location
# return 0 for success, 1 for error
split_file() {
  if [ $# -ne 2 ]; then
    log 2 "'split_file' requires file name, number of pieces"
    return 1
  fi
  file_size=$(stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null)
  part_size=$((file_size / $2))
  remainder=$((file_size % $2))
  if [[ remainder -ne 0 ]]; then
    part_size=$((part_size+1))
  fi

  local error
  if ! error=$(split -a 1 -d -b "$part_size" "$1" "$1"- 2>&1); then
    log 2 "error splitting file: $error"
    return 1
  fi
  return 0
}

# compare files
# input:  two files
# return 0 for same data, 1 for different data, 2 for error
compare_files() {
  if [ $# -ne 2 ]; then
    log 2 "file comparison requires two files"
    return 2
  fi
  log 5 "comparing files '$1' and '$2'"
  os=$(uname)

  if [[ $os == "Darwin" ]]; then
    if ! file_one_md5=$(md5 -q "$1" 2>&1); then
      log 2 "error getting md5 for '$1': $file_one_md5"
      return 2
    fi
    if ! file_two_md5=$(md5 -q "$2" 2>&1); then
      log 2 "error getting md5 for '$2': $file_two_md5"
      return 2
    fi
  else
    if ! file_one_md5=$(md5sum "$1" | cut -d " " -f 1 2>&1); then
      log 2 "error getting md5 for '$1': $file_one_md5"
      return 2
    fi
    if ! file_two_md5=$(md5sum "$2" | cut -d " " -f 1 2>&1); then
      log 2 "error getting md5 for '$2': $file_two_md5"
      return 2
    fi
  fi
  if [[ "$file_one_md5" == "$file_two_md5" ]]; then
    return 0
  fi
  return 1
}

# generate 160MB file
# input: filename
# fail on error
create_large_file() {
  log 6 "create_large_file"
  if [ $# -ne 1 ]; then
    log 2 "'create_large_file' requires file name"
    return 1
  fi

  filesize=$((160*1024*1024))
  if ! error=$(dd if=/dev/urandom of="$TEST_FILE_FOLDER"/"$1" bs=1024 count=$((filesize/1024)) 2>&1); then
    log 2 "error adding data to large file: $error"
    return 1
  fi
  return 0
}

# param: number of files
# fail on error
create_test_file_count() {
  if [ $# -ne 1 ]; then
    log 2 "'create_test_file_count' requires number of files"
    return 1
  fi
  for ((i=1;i<=$1;i++)) {
    if ! error=$(touch "$TEST_FILE_FOLDER/file_$i" 2>&1); then
      log 2 "error creating file_$i: $error"
      return 1
    fi
  }
  # shellcheck disable=SC2153
  if [[ $LOG_LEVEL -ge 5 ]]; then
    ls_result=$(ls "$TEST_FILE_FOLDER/file_*")
    log 5 "$ls_result"
  fi
  return 0
}

download_and_compare_file_with_user() {
  if ! check_param_count_gt "original file, bucket, key, destination, username, password, chunk size (optional)" 6 $#; then
    return 1
  fi
  if ! download_file_with_user "$5" "$6" "$2" "$3" "$4" "$7"; then
    log 2 "error downloading file"
    return 1
  fi
  if ! compare_files "$1" "$4"; then
    log 2 "files don't match"
    return 1
  fi
  return 0
}

download_and_compare_file() {
  log 6 "download_and_compare_file"
  if ! check_param_count_gt "original file, bucket, key, destination, chunk size (optional)" 4 $#; then
    return 1
  fi
  if ! download_and_compare_file_with_user "$1" "$2" "$3" "$4" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$5"; then
    log 2 "error downloading and comparing file with user"
    return 1
  fi
  return 0
}

# params:  src, dst
# fail if error
copy_file_locally() {
  if [ $# -ne 2 ]; then
    log 2 "'copy_file_locally' requires src, dst"
    return 1
  fi
  if ! error=$(cp "$1" "$2" 2>&1); then
    log 2 "error copying file: $error"
    return 1
  fi
  return 0
}

# params: src, dst
# fail if error
move_file_locally() {
  if [ $# -ne 2 ]; then
    log 2 "'move_file_locally' requires src, dst"
    return 1
  fi
  if ! error=$(mv "$1" "$2" 2>&1); then
    log 2 "error moving file: $error"
    return 1
  fi
  return 0
}
