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
    log 2 "error setting up bucket and file"
    return 1
  fi
  return 0
}

setup_bucket_and_file_v3() {
  if ! check_param_count_v2 "bucket env var" 1 $#; then
    return 1
  fi
  if ! bucket_name=$(setup_bucket_v3 "$1" 2>&1); then
    log 2 "error setting up bucket and file: $bucket_name"
    return 1
  fi
  if ! test_file=$(create_test_file_v2 2>&1); then
    log 2 "error creating test file: $test_file"
    return 1
  fi
  echo "$bucket_name $test_file"
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

setup_bucket_and_files_v3() {
  if ! check_param_count_v2 "bucket env var, file count" 2 $#; then
    return 1
  fi
  local bucket_and_files=()
  if ! bucket_name=$(setup_bucket_v3 "$1" 2>&1); then
    log 2 "error setting up bucket"
    return 1
  fi
  bucket_and_files=("$bucket_name")
  for ((i=0;i<$2;i++)); do
    if ! file_name=$(create_test_file_v2 2>&1); then
      log 2 "error creating test file: $file_name"
      return 1
    fi
    bucket_and_files+=("$file_name")
  done
  echo "${bucket_and_files[*]}"
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
  log 5 "create test files: '${*:3}'"
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

setup_bucket_and_large_file_v3() {
  if ! check_param_count_ge_le "bucket env var, file size in MBs (optional)" 1 2 $#; then
    return 1
  fi

  local response bucket_name file_name error
  if ! response=$(setup_bucket_v3 "$1" 2>&1); then
    log 2 "error setting up bucket: $response"
    return 1
  fi
  bucket_name="$response"

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! error=$(create_large_file "$file_name" "$2" 2>&1); then
    log 2 "error creating large file: $error"
    return 1
  fi
  echo "$bucket_name $file_name"
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
  return 0
}

create_test_files_and_folders() {
  if ! check_param_count_gt "any test files, including directories" 1 $#; then
    return 1
  fi

  local file=""
  local dir=""
  local err=""
  for file in "$@"; do
    if ! create_folder_if_needed_and_file "$file"; then
      log 2 "error creating folder if needed and file"
      return 1
    fi
  done
  return 0
}

create_folder_if_needed_and_file() {
  if ! check_param_count_v2 "file path" 1 $#; then
    return 1
  fi
  dir=$(dirname "$1")
  if [ "$dir" != "." ] && [ ! -d "$TEST_FILE_FOLDER/$dir" ]; then
    if ! err=$(mkdir -p "$TEST_FILE_FOLDER/$dir" 2>&1); then
      log 2 "error creating folder '$dir': $err"
      return 1
    fi
  fi
  if ! create_test_file "$file"; then
    log 2 "error creating test file '$file'"
    return 1
  fi
  return 0
}

# optional parameter - file size
# shellcheck disable=SC2120
create_test_file_v2() {
  if ! file_name=$(get_file_name 2>&1); then
    log 2 "error getting file name: $file_name"
    return 1
  fi
  if ! error=$(create_test_file "$file_name" "$1" 2>&1); then
    log 2 "error creating test file: $error"
    return 1
  fi
  echo "$file_name"
  return 0
}

get_file_names() {
  if ! check_param_count_v2 "file name count" 1 $#; then
    return 1
  fi
  file_names=()
  for ((i=0;i<$1;i++)); do
    if ! file_name=$(get_file_name 2>&1); then
      log 2 "error getting file name: $file_name"
      return 1
    fi
    file_names+=("$file_name")
  done
  echo "${file_names[*]}"
  return 0
}

# Usage: create_test_files_with_prefix <prefix> [count]
# Returns: Space-separated list of created filenames
create_test_files_with_prefix() {
  if ! check_param_count_gt "prefix, count (optional)" 1 $#; then
    return 1
  fi

  local prefix="$1"
  local count="${2:-1}"  # Default to 1 if not provided
  local file_names=()
  local file_name
  local error

  for ((i=0; i<count; i++)); do
    # Generate the name
    if ! file_name=$(get_file_name_with_prefix "$prefix" 2>&1); then
      log 2 "error getting file name: $file_name"
      return 1
    fi

    # Create the file
    if ! error=$(create_test_file "$file_name" 2>&1); then
      log 2 "error creating test file: $error"
      return 1
    fi

    file_names+=("$file_name")
  done

  echo "${file_names[*]}"
  return 0
}

# Combined function to setup environment and create test files
# Params: filename1 [filename2 ...]
# Note: Uses $FILE_SIZE if set, otherwise defaults to 10 bytes.  Requires $TEST_FILE_FOLDER.
create_test_files() {
  if ! check_param_count_gt "at least one filename" 1 $#; then
    return 1
  fi

  if [[ -z "$TEST_FILE_FOLDER" ]]; then
    log 2 "TEST_FILE_FOLDER must be defined"
    return 1
  fi

  local file_size="${FILE_SIZE:-10}" # Use global $FILE_SIZE or default to 10
  local error

  log 5 "file size: $file_size"
  for filename in "$@"; do
    local full_path="$TEST_FILE_FOLDER/$filename"

    # Clean up existing file if present
    if ! error=$(rm -f "$full_path" 2>&1); then
      log 2 "error removing existing file $filename: $error"
      return 1
    fi

    # Create the file with random data
    if [[ "$file_size" -eq 0 ]]; then
      touch "$full_path"
    else
      # Use dd for specific size creation
      if ! error=$(dd if=/dev/urandom of="$full_path" bs="$file_size" count=1 conv=notrunc 2>&1); then
        log 2 "error adding $file_size bytes to $filename: $error"
        return 1
      fi
    fi

    log 5 "Created: $full_path ($file_size bytes)"
  done

  return 0
}

create_test_file() {
  if ! check_param_count_gt "file name, size (optional)" 1 $#; then
    return 1
  fi
  if ! error=$(FILE_SIZE="${2:-10}" create_test_files "$1" 2>&1); then
    log 2 "error creating test file: $error"
    return 1
  fi
  return 0
}

create_file_single_char() {
  if ! check_param_count_v2 "filename, size, char" 3 $#; then
    return 1
  fi
  if ! error=$(rm -f "$TEST_FILE_FOLDER/$1" 2>&1); then
    log 2 "error removing existing file: $error"
    return 1
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
  if  ! check_param_count_gt "folder names" 1 $#; then
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
  if ! check_param_count_gt "filenames" 1 $#; then
    return 1
  fi
  if [ -z "$TEST_FILE_FOLDER" ]; then
    log 2 "no test file folder defined, not deleting"
    return 1
  fi
  for name in "$@"; do
    if ! error=$(rm -f "${TEST_FILE_FOLDER:?}"/"${name:?}" 2>&1); then
      log 2 "error deleting file '$name': $error"
    fi
  done
  return 0
}

get_file_size() {
  if ! check_param_count_v2 "file location" 1 $#; then
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
  if ! check_param_count_v2 "file name, number of pieces" 2 $#; then
    return 1
  fi
  # -n l/K : Split into K pieces without breaking lines (or use 'K' for raw bytes)
  # -d     : Use numeric suffixes
  # -a 2   : Allow up to 100 pieces (00-99)
  if ! error=$(split -a 2 -d -n "$2" "$1" "${1}-" 2>&1); then
    log 2 "error splitting file: $error"
    return 1
  fi

  local restore_nullglob
  restore_nullglob="$(shopt -p nullglob)"
  shopt -s nullglob

  local parts=("${1}-"*)

  eval "$restore_nullglob"

  if [ "${#parts[@]}" -eq 0 ]; then
    log 2 "split produced no output files"
    return 1
  fi

  echo "${parts[*]}" | sort
  return 0
}

compare_files() {
   if ! check_param_count_v2 "two files" 2 $#; then
    return 2
  fi
  log 5 "comparing files '$1' and '$2'"

  local file1="$1"
  local file2="$2"
  local md5_cmd
  local f1_sum f2_sum

  if [[ "$(uname)" == "Darwin" ]]; then
    md5_cmd="md5 -q"
  else
    md5_cmd="md5sum"
  fi

  if ! f1_raw=$($md5_cmd "$file1" 2>&1); then
    log 2 "error getting md5 for '$file1': $f1_raw"
    return 2
  fi
  # Clean the output (extract just the hex hash)
  f1_sum=$(echo "$f1_raw" | awk '{print $1}')

  if ! f2_raw=$($md5_cmd "$file2" 2>&1); then
    log 2 "error getting md5 for '$file2': $f2_raw"
    return 2
  fi
   # Clean the output (extract just the hex hash)
  f2_sum=$(echo "$f2_raw" | awk '{print $1}')

  if [[ "$f1_sum" == "$f2_sum" ]]; then
    return 0
  fi

  log 2 "MD5 mismatch: $f1_sum ($file1) vs $f2_sum ($file2)"
  return 1
}

# generate 160MB file
# input: filename
# fail on error
create_large_file() {
  log 6 "create_large_file"
  if ! check_param_count_ge_le "file name, size in MBs (optional)" 1 2 $#; then
    return 1
  fi
  file_size=${2:-160}
  if ! error=$(create_large_file_with_size "$1" "$file_size" 2>&1); then
    log 2 "error creating 160MB file: $error"
    return 1
  fi
  return 0
}

create_large_file_v2() {
  local response file_name
  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! error=$(create_large_file_with_size "$file_name" 160 2>&1); then
    log 2 "error creating 160MB file with name '$file_name': $error"
    return 1
  fi
  echo "$file_name"
  return 0
}

create_large_file_with_size() {
  if ! check_param_count_v2 "file name, size in MB" 2 $#; then
    return 1
  fi
  file_size=$(($2*1024*1024))
  if ! error=$(create_test_file_base "$1" "$file_size" 2>&1); then
    log 2 "error creating large file with size ${2}MB: $error"
    return 1
  fi
  return 0
}

create_test_file_base() {
  if ! check_param_count_ge_le "file name, size (optional), block size (optional)" 1 3 $#; then
    return 1
  fi
  log 5 "params: $*"

  local file_name=$1
  local requested_size=${2:-10}
  local block_size=${3:-1048576}

  if [ "$file_name" == "" ]; then
    log 2 "no file name specified"
    return 1
  fi
  local full_path="$TEST_FILE_FOLDER/$file_name"

  if [[ "$requested_size" -eq 0 ]]; then
    touch "$full_path"
  elif [[ "$requested_size" -lt "$block_size" ]]; then
    # For small files, use the size as the block size (1 write)
    if ! error=$(dd if=/dev/urandom of="$full_path" bs="$requested_size" count=1 conv=notrunc 2>&1); then
      log 2 "error writing file: $error"
      return 1
    fi
  else
    # For large files, use 1MB chunks to save RAM
    count=$(( requested_size / block_size ))
    remainder=$(( requested_size % block_size ))

    # Write the big 1MB chunks
    if ! error=$(dd if=/dev/urandom of="$full_path" bs="$block_size" count="$count" conv=notrunc 2>&1); then
      log 2 "error writing file chunk: $error"
      return 1
    fi

    # If there's a remainder (e.g., 1.5MB), append the last few bytes
    if [[ $remainder -gt 0 ]] && ! error=$(dd if=/dev/urandom of="$full_path" bs=1 count="$remainder" oflag=append conv=notrunc 2>&1); then
      log 2 "error writing final file chunk: $error"
      return 1
    fi
  fi
  echo "$file_name"
  return 0
}

create_and_split_large_file() {
if ! check_param_count_v2 "file name, size in MB, pieces" 3 $#; then
  return 1
fi
if ! error=$(create_large_file_with_size "$1" "$2" 2>&1); then
  log 2 "error creating large file: $error"
  return 1
fi
if ! split_file "$TEST_FILE_FOLDER/$1" "$3"; then
  log 2 "error splitting file"
  return 1
fi
}

# param: number of files
# fail on error
create_test_file_count() {
  if ! check_param_count_v2 "number of files" 1 $#; then
    return 1
  fi
  if [ -z "$TEST_FILE_FOLDER" ]; then
    log 2 "TEST_FILE_FOLDER not defined"
    return 1
  fi

  local response file_prefix
  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file prefix: $response"
    return 1
  fi
  file_prefix="$response"

  for ((i=1;i<=$1;i++)) {
    if ! error=$(touch "$TEST_FILE_FOLDER/${file_prefix}_${i}" 2>&1); then
      log 2 "error creating file_$i: $error"
      return 1
    fi
  }
  # shellcheck disable=SC2153
  if [[ $LOG_LEVEL -ge 5 ]]; then
    ls_result=$(ls "$TEST_FILE_FOLDER/${file_prefix}_*" 2>&1)
    log 5 "$ls_result"
  fi
  echo "$file_prefix"
  return 0
}

download_and_compare_file_with_user() {
  if ! check_param_count_gt "original file, bucket, key, destination, username, password, chunk size (optional)" 6 $#; then
    return 1
  fi
  if [ -e "$4" ] && ! error=$(rm -f "$4" 2>&1); then
    log 2 "error deleting local file at download destination before download: $error"
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
  if ! check_param_count_v2 "src, dst" 2 $#; then
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
  if ! check_param_count_v2 "src,dst" 2 $#; then
    return 1
  fi
  if ! error=$(mv "$1" "$2" 2>&1); then
    log 2 "error moving file: $error"
    return 1
  fi
  return 0
}
