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

compare_website_suffixes() {
  if ! check_param_count_v2 "data file, expected suffix" 2 $#; then
    return 1
  fi
  local data_file="$1" expected_suffix="$2"

  if ! check_xml_element "$data_file" "$expected_suffix" "WebsiteConfiguration" "IndexDocument" "Suffix"; then
    log 2 "error checking xml element"
    return 1
  fi
  return 0
}

check_index_document_suffix() {
  if ! check_param_count_v2 "bucket name, expected suffix" 2 $#; then
    return 1
  fi
  local bucket_name="$1" expected_suffix="$2"

  if ! send_rest_go_command_callback "200" "compare_website_suffixes" "-bucketName" "$bucket_name" "-query" "website" "--" "$expected_suffix"; then
    log 2 "error sending get website command or comparing suffix"
    return 1
  fi
  return 0
}