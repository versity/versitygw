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

get_check_tag_error_with_invalid_key() {
  if ! check_param_count_v2 "bucket name, key, tag key, tag value" 4 $#; then
    return 1
  fi
  invalid_key="$3"
  if ! send_rest_go_command_expect_error_callback "400" "InvalidTag" "The TagKey you have provided is invalid" "check_invalid_key_error" \
     "-bucketName" "$1" "-objectKey" "$2" "-commandType" "putObjectTagging" "-tagKey" "$3" "-tagValue" "$4" "-contentMD5"; then
    log 2 "error sending put tag command or checking callback"
    return 1
  fi
  return 0
}

check_invalid_key_error() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_error_parameter "$1" "TagKey" "$invalid_key"; then
    log 2 "error checking 'TagKey' parameter"
    return 1
  fi
  return 0
}