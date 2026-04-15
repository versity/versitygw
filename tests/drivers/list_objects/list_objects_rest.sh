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

list_check_single_object() {
  if ! check_param_count_gt "bucket, key, env params (optional)" 2 $#; then
    return 1
  fi

  local response
  if ! response=$(list_objects_rest "$1" "parse_objects_list_rest" "$3" 2>&1); then
    log 2 "error listing objects: $response"
    return 1
  fi
  mapfile -t object_array <<< "$response"
  if [ ${#object_array[@]} -ne "1" ]; then
    log 2 "expected one object, found ${#object_array[@]}"
    return 1
  fi
  if [ "${object_array[0]}" != "$2" ]; then
    log 2 "expected '$2', was '${object_array[0]}'"
    return 1
  fi
  return 0
}

list_objects_success_or_access_denied() {
  if ! check_param_count_v2 "username, password, bucket, key, expect success" 5 $#; then
    return 1
  fi
  log 5 "true or false: $5"
  if [ "$5" == "true" ]; then
    if ! list_check_single_object "$3" "$4" "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2"; then
      log 2 "expected ListObjects to succeed, didn't"
      return 1
    fi
  else
    if ! list_objects_rest_expect_error "$3" "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2" "403" "AccessDenied" "Access Denied"; then
      log 2 "expected ListObjects access denied"
      return 1
    fi
  fi
  return 0
}

check_v2_objects() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_xml_element "$1" "$object_count" "ListBucketResult" "KeyCount"; then
    log 2 "error checking KeyCount element"
    return 1
  fi
  for object in "${expected_objects[@]}"; do
    if ! check_if_element_exists "$1" "$object" "ListBucketResult" "Contents" "Key"; then
      log 2 "error checking if element '$object' exists"
      return 1
    fi
  done
  return 0
}

list_check_objects_rest_v2() {
  if ! check_param_count_v2 "bucket name, object count, objects, params" 4 $#; then
    return 1
  fi
  object_count=$2
  expected_objects=("${@:3:$object_count}")
  if ! list_objects_v2_rest_callback "$1" "200" "check_v2_objects" "${@:((3+$object_count))}"; then
    log 2 "error sending list objects v2 command and checking callback"
    return 1
  fi
}

check_single_common_prefix_or_key() {
  if ! check_param_count_v2 "data file, parameter, prefix or not" 3 $#; then
    return 1
  fi
  if [ "$3" == "true" ]; then
    if ! check_if_element_exists "$1" "$2" "ListBucketResult" "CommonPrefixes" "Prefix"; then
      log 2 "error checking if CommonPrefix '$2' exists"
      return 1
    fi
  else
    if ! check_if_element_exists "$1" "$2" "ListBucketResult" "Contents" "Key"; then
      log 2 "error checking if Key '$2' exists"
      return 1
    fi
  fi
  return 0
}

check_common_prefixes_and_keys() {
  if ! check_param_count_gt "data file, prefix, delimiter, common prefixes, --, keys" 4 $#; then
    return 1
  fi
  if ! xml_data=$(check_validity_and_or_parse_xml_data "$1" 2>&1); then
    log 2 "error parsing xml data: $xml_data"
    return 1
  fi
  local checking_prefixes="true" prefix_count=0 key_count=0
  for param in "${@:4}"; do
    if [ "$param" == "--" ]; then
      checking_prefixes=false
      continue
    fi
    if ! check_single_common_prefix_or_key "$xml_data" "$param" "$checking_prefixes"; then
      log 2 "error checking if common prefix or key '$param' exists"
      return 1
    fi
    if [ "$checking_prefixes" == "true" ]; then
      ((prefix_count++))
    else
      ((key_count++))
    fi
  done
  if ! check_prefix_delimiter_and_counts "$xml_data" "$2" "$3" "$prefix_count" "$key_count"; then
    log 2 "error checking prefix"
    return 1
  fi
  return 0
}

check_prefix_delimiter_and_counts() {
  if ! check_param_count_v2 "data, prefix, delimiter, prefix count, key count" 5 $#; then
    return 1
  fi
  if ! check_xml_element "$1" "$2" "ListBucketResult" "Prefix"; then
    log 2 "error checking prefix"
    return 1
  fi
  if ! check_xml_element "$1" "$3" "ListBucketResult" "Delimiter"; then
    log 2 "error checking delimiter"
    return 1
  fi
  if ! check_element_count "$1" "$4" "ListBucketResult" "CommonPrefixes" "Prefix"; then
    log 2 "Prefix count mismatch"
    return 1
  fi
  if ! check_element_count "$1" "$5" "ListBucketResult" "Contents" "Key"; then
    log 2 "Prefix count mismatch"
    return 1
  fi
  return 0
}

list_objects_with_prefix_and_delimiter_check_results() {
  if ! check_param_count_gt "bucket name, ListObjects version, prefix, delimiter, expected common prefixes, --, expected keys" 6 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_common_prefixes_and_keys" "-bucketName" "$1" "-query" "list-type=$2&delimiter=$4&prefix=$3" "--" "${@:3}"; then
    log 2 "error sending command to list objects or receiving response"
    return 1
  fi
  return 0
}

list_objects_check_key() {
  if ! check_param_count_v2 "bucket name, key, encoding type" 3 $#; then
    return 1
  fi
  query=()
  if [ "$3" != "" ]; then
    query=("-query" "encoding-type=$3")
  fi
  if ! send_rest_go_command_callback "200" "check_if_key_exists" "-bucketName" "$1" "${query[@]}" "--" "$2"; then
    log 2 "error sending rest command"
    return 1
  fi
  return 0
}

check_if_key_exists() {
  if ! check_param_count_v2 "data file, key" 2 $#; then
    return 1
  fi
  if ! check_if_element_exists "$1" "$2" "ListBucketResult" "Contents" "Key"; then
    log 2 "error checking if CommonPrefix '$2' exists"
    return 1
  fi
  return 0
}

check_count_and_keys() {
  if ! check_param_count_gt "data file, count, keys" 2 $#; then
    return 1
  fi
  if ! xml_data=$(check_validity_and_or_parse_xml_data "$1" 2>&1); then
    log 2 "error parsing xml data: $xml_data"
    return 1
  fi
  if ! check_element_count "$xml_data" "$2" "ListBucketResult" "Contents" "Key"; then
    log 2 "error checking element count"
    return 1
  fi
  for key in "${@:3}"; do
    if ! check_if_element_exists "$xml_data" "$key" "ListBucketResult" "Contents" "Key"; then
      log 2 "error checking if element '$key' exists"
      return 1
    fi
  done
  echo "$xml_data"
  return 0
}

list_objects_check_count_and_keys() {
  if ! check_param_count_gt "bucket name, count, keys, additional params if any" 1 $#; then
    return 1
  fi
  local count="$2"
  local keys=("${@:3:$count}")
  if ! send_rest_go_command_callback "200" "check_count_and_keys" "-bucketName" "$1" "${@:((3+$count))}" "--" "$count" "${keys[@]}"; then
    log 2 "error sending list objects command"
    return 1
  fi
  return 0
}

check_count_keys_and_get_token() {
  if ! check_param_count_gt "data file, expected continuation token, count, last keys, keys" 4 $#; then
    return 1
  fi

  local response error
  if ! response=$(check_count_and_keys "$1" "$3" "${@:5}" 2>&1); then
    log 2 "error checking count and keys: $response"
    return 1
  fi

  xml_file="$response"
  if [ "$2" != "" ] && ! error=$(check_if_element_exists "$xml_file" "$2" "ListBucketResult" "ContinuationToken" 2>&1); then
    log 2 "error getting continuation token: $error"
    return 1
  fi
  if [ "$4" == "false" ]; then
    if ! response=$(get_element_text "$xml_file" "ListBucketResult" "NextContinuationToken" 2>&1); then
      log 2 "error getting next continuation token: $response"
      return 1
    fi
    next_continuation_token="$response"
  else
    if response=$(get_element_text "$xml_file" "ListBucketResult" "NextContinuationToken" 2>/dev/null) && [ -n "$response" ]; then
      log 2 "last element shouldn't have 'NextConfigurationToken' value"
      return 1
    fi
    next_continuation_token=
  fi
  echo "$next_continuation_token"
  return 0
}

list_objects_v2_check_count_and_keys_get_token() {
  if ! check_param_count_gt "bucket name, expected token, count, last keys, keys, additional params if any" 4 $#; then
    return 1
  fi
  local count="$3"
  local keys=("${@:5:$count}")
  if ! callback_response=$(send_rest_go_command_callback "200" "check_count_keys_and_get_token" "-bucketName" "$1" "${@:((5+$count))}" "--" "$2" "$count" "$4" "${keys[@]}" 2>&1); then
    log 2 "error sending list objects command: $callback_response"
    return 1
  else
    continuation_token="$callback_response"
  fi
  echo "$continuation_token"
  return 0
}

check_start_after_no_continuation_token() {
  if ! check_param_count_v2 "bucket, last file in alphabetical order" 2 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "verify_element_doesnt_exist" "-bucketName" "$1" "-query" "start-after=$2&list-type=2" "--" "$2" "ListBucketResult" "ContinuationToken"; then
    log 2 "error verifying that ContinuationToken value is not returned"
    return 1
  fi
  return 0
}

list_objects_check_start_after_response() {
  if ! check_param_count_gt "bucket, start after token, listed files" 2 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_start_after_response" "-bucketName" "$1" "-query" "start-after=$2&list-type=2" "--" "$2" "${@:3}"; then
    log 2 "error listing objects and checking start-after response"
    return 1
  fi
  return 0
}

check_start_after_response() {
  if ! check_param_count_gt "data file, start after file, listed files" 2 $#; then
    return 1
  fi

  local response
  if ! response=$(check_validity_and_or_parse_xml_data "$1" 2>&1); then
    log 2 "error parsing xml data: $response"
    return 1
  fi

  xml_data="$response"
  if ! check_if_element_exists "$xml_data" "$2" "ListBucketResult" "StartAfter"; then
    log 2 "error checking if element '$2' exists"
    return 1
  fi
  local count
  if [ "$3" == "" ]; then
    count=0
  else
    count=$(($#-2))
  fi
  if ! check_element_count "$xml_data" "$count" "ListBucketResult" "Contents" "Key"; then
    log 2 "error checking element count"
    return 1
  fi
  for file_name in "${@:3}"; do
    if ! check_if_element_exists "$xml_data" "$file_name" "ListBucketResult" "Contents" "Key"; then
      log 2 "error checking if element '$file_name' exists"
      return 1
    fi
  done
  return 0
}

list_objects_verify_owner_info_missing() {
  if ! check_param_count_gt "bucket name, files" 1 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "verify_owner_info_missing" "-bucketName" "$1" "-query" "list-type=2&fetch-owner=false" "--" "${@:2}"; then
    log 2 "error sending list objects v2 command and verifying that the owner data is missing"
    return 1
  fi
}

verify_owner_info_missing() {
  if ! check_param_count_gt "data file, files" 1 $#; then
    return 1
  fi

  local response
  for key in "${@:2}"; do
    if ! response=$(get_element_with_matching_inner_value "$1" "$key" "ListBucketResult" "Contents" "--" "Key" 2>&1); then
      log 2 "error finding element matching key '$key': $response"
      return 1
    fi
    element="$response"

    if check_xml_element_inside_string "$element" "$AWS_ACCESS_KEY_ID" "Owner" "ID"; then
      log 2 "'Owner' value should not be present"
      return 1
    fi
  done
  return 0
}

list_objects_verify_owner_info_exists() {
  if ! check_param_count_gt "bucket name, files" 1 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "verify_owner_info_exists" "-bucketName" "$1" "-query" "list-type=2&fetch-owner=true" "--" "${@:2}"; then
    log 2 "error sending list objects v2 command and verifying that the owner data is missing"
    return 1
  fi
}

verify_owner_info_exists() {
  if ! check_param_count_gt "data file, files" 1 $#; then
    return 1
  fi

  local response
  for key in "${@:2}"; do
    if ! response=$(get_element_with_matching_inner_value "$1" "$key" "ListBucketResult" "Contents" "--" "Key" 2>&1); then
      log 2 "error finding element matching key '$key': $response"
    else
      element="$response"
    fi
    if ! check_xml_element_inside_string "$element" "$AWS_ACCESS_KEY_ID" "Owner" "ID"; then
      log 2 "'Owner' value missing"
      return 1
    fi
  done
  return 0
}
