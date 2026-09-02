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

check_redirect_response() {
  if ! check_param_count_v2 "URL, redirect URL" 2 $#; then
    return 1
  fi
  local url="$1" redirect_url="$2"
  local response response_file

  if ! response=$(curl -ksi "http://${url}" 2>&1); then
    log 2 "error sending curl message: $response"
    return 1
  fi
  if [[ "$response" != *"HTTP/1.1 301"* ]]; then
    log 2 "expected 301 response (response: '$response')"
    return 1
  fi
  if ! response_file=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response_file"
    return 1
  fi
  echo "$response" > "$TEST_FILE_FOLDER/$response_file"
  if ! check_header_key_and_value "$TEST_FILE_FOLDER/$response_file" "Location" "http://$redirect_url/"; then
    log 2 "error checking redirect header key and value (data: '$response')"
    return 1
  fi
  return 0
}