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

  if ! response=$(put_object_with_random_alnum_string "$bucket_name" 2>&1); then
    log 2 "error putting object with random alnum string: $response"
    return 1
  fi
  read -r file_name test_string <<< "$response"

  if ! response=$(send_rest_go_command "200" "-commandType" "putBucketWebsiteConfiguration" "-bucketName" "$bucket_name" \
      "-websiteConfiguration" "{\"IndexDocument\":{\"Suffix\":\"$file_name\"}}" 2>&1); then
    log 2 "error putting website configuration: $response"
    return 1
  fi
  printf '%s\n' "$file_name $test_string"
  return 0
}