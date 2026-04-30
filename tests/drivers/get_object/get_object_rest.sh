#!/usr/bin/env bash

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

get_object_success_or_access_denied() {
  if ! check_param_count_v2 "username, password, bucket, key, output file, expect success" 6 $#; then
    return 1
  fi
  if [ "$6" == "true" ]; then
    if ! get_object_rest_with_user "$1" "$2" "$3" "$4" "$5"; then
      log 2 "expected GetObject to succeed, didn't"
      return 1
    fi
  else
    if ! get_object_rest_expect_error "$3" "$4" "$5" "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2" "403" "AccessDenied" "Access Denied"; then
      log 2 "expected GetObject access denied"
      return 1
    fi
  fi
  return 0
}

test_get_object_with_custom_content_header() {
  if ! check_param_count_v2 "header key, value" 2 $#; then
    return 1
  fi
  if ! response=$(setup_bucket_and_file_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up bucket and file: $response"
    return 1
  fi
  read -r bucket_name file_name <<< "$response"

  if ! result=$(put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name" 2>&1); then
    log 2 "error putting object: $result"
    return 1
  fi
  if ! result=$(send_rest_go_command_callback "200" "check_for_header_key_and_value" "-bucketName" "$bucket_name" "-objectKey" "$file_name" "-query" "response-$1=$2" \
    "--" "$1" "$2" 2>&1); then
      log 2 "error sending command and checking header: $result"
      return 1
  fi
  return 0
}

validate_partial_content_response() {
  if ! check_param_count_v2 "header data, part number, downloaded part file, original part file, original file size, first part size" 6 $#; then
    return 1
  fi

  starting_byte=$((($2-1)*$6))
  ending_byte=$(($2*$6-1))
  if [ "$5" -lt "$ending_byte" ]; then
    ending_byte="$(($5-1))"
  fi
  content_range_string="bytes $starting_byte-$ending_byte/$5"
  if ! result=$(check_for_header_key_and_value "$1" "Content-Range" "$content_range_string" 2>&1); then
    log 2 "error checking for header key and value: $result"
    return 1
  fi

  if ! result=$(compare_files "$3" "$4" 2>&1); then
    log 2 "error comparing data files: $result"
    return 1
  fi
  return 0
}

send_get_object_with_part_number_validate_response() {
  if ! check_param_count_v2 "bucket name, key, part number, part data file, original file size, first part size" 6 $#; then
    return 1
  fi
  if ! response=$(get_file_names 2 2>&1); then
    log 2 "error getting file names: $response"
    return 1
  fi
  read -r header_file output_file <<< "$response"
  log 5 "output file: $output_file"
  if ! send_rest_go_command_callback "206" "validate_partial_content_response" "-bucketName" "$1" "-objectKey" "$2" "-query" "partNumber=$3" \
      "-headerFile" "$TEST_FILE_FOLDER/$header_file" "-outputFile" "$TEST_FILE_FOLDER/$output_file" "--" "$3" "$4" "$TEST_FILE_FOLDER/$output_file" "$5" "$6"; then
    log 2 "error sending rest go command"
    return 1
  fi
  return 0
}
