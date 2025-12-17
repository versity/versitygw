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

source ./tests/drivers/put_object_tagging/put_object_tagging_rest.sh

parse_object_tags_rest() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  log 5 "object tags: $(cat "$1")"
  if ! tag_set_key=$(get_element_text "$1" "Tagging" "TagSet" "Tag" "Key" 2>&1); then
    log 2 "error getting key: $tag_set_key"
    return 1
  fi
  if ! tag_set_value=$(get_element_text "$1" "Tagging" "TagSet" "Tag" "Value" 2>&1); then
    log 2 "error getting value: $tag_set_value"
    return 1
  fi
  return 0
}

get_check_object_tags_single_set_go() {
  if ! check_param_count_gt "bucket, key, expected tag key, expected tag value, params" 4 $#; then
    return 1
  fi
  expected_key="$3"
  expected_value="$4"
  if ! send_rest_go_command_callback "200" "check_object_tags_single_set" "-bucketName" "$1" "-objectKey" "$2" "-method" "GET" \
      "-query" "tagging=" "${@:5}"; then
    log 2 "error sending go command or callback error"
    return 1
  fi
}

check_object_tags_single_set() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! parse_object_tags_rest "$1"; then
    log 2 "error parsing object tags"
    return 1
  fi
  if [ "$tag_set_key" != "$expected_key" ]; then
    log 2 "key mismatch, expected '$expected_key', was '$tag_set_key'"
    return 1
  fi
  if [ "$tag_set_value" != "$expected_value" ]; then
    log 2 "key mismatch, expected '$expected_value', was '$tag_set_value'"
    return 1
  fi
  return 0
}

check_for_empty_tagset() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_for_empty_element "$1" "Tagging" "TagSet"; then
    log 2 "error checking for empty XML element"
    return 1
  fi
  return 0
}

get_check_object_tags_empty() {
  if ! check_param_count_v2 "bucket name, key" 2 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_for_empty_tagset" "-bucketName" "$1" "-objectKey" "$2" \
      "-method" "GET" "-query" "tagging="; then
    log 2 "error sending get object tagging command"
    return 1
  fi
  return 0
}

check_header_version_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_for_header_key_and_value "$1" "x-amz-version-id" "$version_id"; then
    log 2 "error checking for x-amz-version-id header"
    return 1
  fi
  return 0
}

add_version_tags_check_version_id() {
  if ! check_param_count_v2 "bucket name, key" 2 $#; then
    return 1
  fi
  if ! tag_old_version "$1" "$2"; then
    log 2 "error tagging old version"
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_header_version_id" "-bucketName" "$1" "-objectKey" "$2" "-debug" "-logFile" "signature.log" \
        "-method" "GET" "-query" "tagging=&versionId=$version_id" "-tagKey" "key" "-tagValue" "value" "-contentMD5"; then
    log 2 "error tagging object"
    return 1
  fi
  return 0
}

check_invalid_version_id_error() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_error_parameter "$1" "ArgumentName" "versionId"; then
    return 1
  fi
  if ! check_error_parameter "$1" "ArgumentValue" "$invalid_version_id"; then
    return 1
  fi
  return 0
}

get_object_tagging_invalid_version_id() {
  if ! check_param_count_v2 "bucket name, key" 2 $#; then
    return 1
  fi
  invalid_version_id="$2"
  if ! send_rest_go_command_expect_error_callback "400" "InvalidArgument" "Invalid version id specified" "check_invalid_version_id_error" \
      "-bucketName" "$1" "-objectKey" "$2" "-debug" "-logFile" "signature.log" \
      "-method" "GET" "-query" "tagging=&versionId=$invalid_version_id" "-tagKey" "key" "-tagValue" "value" "-contentMD5"; then
    log 2 "error tagging object"
    return 1
  fi
  return 0
}
