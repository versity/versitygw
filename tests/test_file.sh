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
source ./tests/drivers/file.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/commands/put_object.sh

assert_test_file_folder_exists() {
  if [ -z "$TEST_FILE_FOLDER" ] || [ ! -d "$TEST_FILE_FOLDER" ]; then
    echo "TEST_FILE_FOLDER must be set and exist" >&2
    return 1
  fi
  return 0
}

# shellcheck disable=SC2030
@test "test - download_and_compare_file" {
  file_exists_in_dest_location=("true" "false")
  pass_or_fail=("true" "false")
  for exists in "${file_exists_in_dest_location[@]}"; do
    for pass in "${pass_or_fail[@]}"; do
      test_download_and_compare_file "$exists" "$pass"
    done
  done
}

test_download_and_compare_file() {
  if ! check_param_count_v2 "existing file, pass" 2 $#; then
    return 1
  fi
  log 5 "existing file: $1, pass: $2"
  assert_test_file_folder_exists

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  # shellcheck disable=SC2031
  bucket_name="$output"

  run get_file_name
  assert_success
  # shellcheck disable=SC2031
  object_key="$output"

  src_file="$TEST_FILE_FOLDER/src_${object_key}"
  printf '%s' "source-payload" > "$src_file"
  existing_or_not_dst_file="$TEST_FILE_FOLDER/dst_${object_key}"
  if [ "$1" == "true" ]; then
    printf '%s' "other-payload" > "$existing_or_not_dst_file"
  fi
  if [ "$2" == "false" ]; then
    bad_src_file="$TEST_FILE_FOLDER/bad_src_${object_key}"
    printf '%s' "wrong-payload" > "$src_file"
    compare_file="$bad_src_file"
  else
    compare_file="$src_file"
  fi

  run put_object_rest "$src_file" "$bucket_name" "$object_key"
  assert_success

  run download_and_compare_file "$compare_file" "$bucket_name" "$object_key" "$existing_or_not_dst_file"
  if [ "$2" == "true" ]; then
    assert_success
  else
    assert_failure
  fi
}
