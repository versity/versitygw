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

objects_versions_invalid_encoding() {
  if ! check_param_count_v2 "base query" 1 $#; then
    return 1
  fi
  local response bucket_name file_name query=""

  if [ "$1" != "" ]; then
    query="$1&"
  fi

  if ! response=$(setup_bucket_and_file_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up bucket and file: $response"
    return 1
  fi
  read -r bucket_name file_name <<< "$response"

  if ! response=$(send_rest_go_command "200" "-method" PUT "-bucketName" "$bucket_name" "-payloadFile" "$TEST_FILE_FOLDER/$file_name" "-objectKey" "$file_name" 2>&1); then
    log 2 "error sending put object command: $response"
    return 1
  fi

  local bad_encoding="jdfkllaj"
  if ! response=$(send_rest_go_command_expect_error_with_arg_name_value "400" "InvalidArgument" "Invalid Encoding Method specified in Request" \
    "encoding-type" "$bad_encoding" "-bucketName" "$bucket_name" "-query" "${query}encoding-type=$bad_encoding" 2>&1); then
      log 2 "error checking for invalid encoding"
      return 1
  fi
  return 0
}

objects_versions_encoding_success() {
  if ! check_param_count_v2 "base query, base element, object element" 3 $#; then
    return 1
  fi
  local response bucket_name file_name expected_encoding payload_file

  if ! response=$(setup_bucket_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up bucket: $response"
    return 1
  fi
  bucket_name="$response"

  file_name="a+ b.txt"
  expected_encoding="a%2B+b.txt"
  if ! create_test_file "$file_name"; then
    log 2 "error creating test file"
    return 1
  fi

  payload_file="$TEST_FILE_FOLDER/$file_name"
  if ! send_rest_go_command "200" "-method" "PUT" "-payloadFile" "$payload_file" "-bucketName" "$bucket_name" "-objectKey" "$file_name"; then
    log 2 "error sending PutObject command"
    return 1
  fi

  if ! list_objects_check_key "$bucket_name" "$expected_encoding" "url" "$1" "$2" "$3"; then
    log 2 "error checking object matches expected encoding"
    return 1
  fi

  if ! list_objects_check_key "$bucket_name" "$file_name" "" "$1" "$2" "$3"; then
    log 2 "error checking that object isn't encoded without url param"
    return 1
  fi
  return 0
}

list_objects_check_key() {
  if ! check_param_count_v2 "bucket name, key, encoding type, additional query, main element, object element" 6 $#; then
    return 1
  fi
  local query_params=() query
  if [ "$3" != "" ]; then
    query="encoding-type=$3"
    if [ "$4" != "" ]; then
      query+="&$4"
    fi
  elif [ "$4" != "" ]; then
    query="$4"
  fi
  if [ "$query" != "" ]; then
    query_params=("-query" "$query")
  fi
  if ! send_rest_go_command_callback "200" "check_if_key_exists" "-bucketName" "$1" "${query_params[@]}" "--" "$2" "$5" "$6"; then
    log 2 "error sending rest command"
    return 1
  fi
  return 0
}

check_if_key_exists() {
  if ! check_param_count_v2 "data file, key, main element, object element" 4 $#; then
    return 1
  fi
  if ! check_if_element_exists "$1" "$2" "$3" "$4" "Key"; then
    log 2 "error checking if Key '$2' exists"
    return 1
  fi
  return 0
}

setup_delimiter_test() {
  local response bucket_name file_names=() prefix

  if ! response=$(setup_bucket_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up bucket: $response"
    return 1
  fi
  bucket_name="$response"

  file_names=("a-b-1.txt" "a-b-2.txt" "a-b/c-1.txt" "a-b/c-2.txt" "a-b/d.txt" "a/c.txt")
  prefix="a-"

  if ! create_test_files_and_folders "${file_names[@]}"; then
    log 2 "error creating test files and folders"
    return 1
  fi

  for file_name in "${file_names[@]}"; do
    if ! put_object "rest" "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"; then
      log 2 "error putting object '$file_name'"
      return 1
    fi
  done
  echo "$bucket_name"
  echo "$prefix"
  return 0
}
