#!/usr/bin/env bash

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

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/string.sh

create_website_with_random_string() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  local bucket_name="$1"
  local response file_name test_string

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! response=$(generate_random_string 8 10 2>&1); then
    log 2 "error generating random string: $response"
    return 1
  fi
  test_string="$response"
  echo "$test_string" > "$TEST_FILE_FOLDER/$file_name"

  if ! response=$(put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name" 2>&1); then
    log 2 "error putting random string file: $response"
    return 1
  fi

  if ! response=$(send_rest_go_command "200" "-commandType" "putBucketWebsiteConfiguration" "-bucketName" "$bucket_name" \
      "-websiteConfiguration" "{\"IndexDocument\":{\"Suffix\":\"$file_name\"}}" 2>&1); then
    log 2 "error putting website configuration: $response"
    return 1
  fi
  printf '%s\n' "$test_string"
  return 0
}