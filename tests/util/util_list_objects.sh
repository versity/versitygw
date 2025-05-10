#!/usr/bin/env bash

source ./tests/commands/list_objects_v2.sh
source ./tests/util/util_xml.sh

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

parse_objects_list_rest() {
  object_array=()
  # shellcheck disable=SC2154
  log 5 "reply: $reply"
  if ! object_list=$(echo "$reply" | xmllint --xpath '//*[local-name()="Key"]/text()' - 2>&1); then
    if [[ "$object_list" == *"XPath set is empty"* ]]; then
      return 0
    fi
    log 2 "error getting object list: $object_list"
    return 1
  fi
  log 5 "object list: '$object_list'"
  while IFS= read -r object; do
    log 5 "parsed key: '$object'"
    object_array+=("$(echo -n "$object" | xmlstarlet unesc)")
  done <<< "$object_list"
  log 5 "object array: ${object_array[*]}"
  return 0
}

list_check_single_object() {
  if ! check_param_count "list_check_single_object" "bucket, key" 2 $#; then
    return 1
  fi
  if ! list_objects "rest" "$1"; then
    log 2 "error listing objects"
    return 1
  fi
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

list_check_objects_v1() {
  if ! check_param_count "list_check_objects_v1" "bucket, expected key one, expected size one, expected key two, expected size two" 5 $#; then
    return 1
  fi
  if ! list_objects_s3api_v1 "$1"; then
    log 2 "error listing objects (s3api, v1)"
    return 1
  fi
  if ! check_listed_objects "$2" "$3" "$4" "$5"; then
    log 2 "error checking listed objects"
    return 1
  fi
  return 0
}

check_listed_objects() {
  if ! check_param_count "check_listed_objects" "expected key one, expected size one, expected key two, expected size two" 4 $#; then
    return 1
  fi
  # shellcheck disable=SC2154
  if ! key_one=$(echo "$objects" | jq -r '.Contents[0].Key' 2>&1); then
    log 2 "error obtaining key one: $key_one"
    return 1
  fi
  if [[ $key_one != "$1" ]]; then
    log 2 "Object one mismatch ($key_one, $1)"
    return 1
  fi
  if ! size_one=$(echo "$objects" | jq -r '.Contents[0].Size' 2>&1); then
    log 2 "error obtaining size one: $size_one"
    return 1
  fi
  if [[ $size_one -ne "$2" ]]; then
    log 2 "Object one size mismatch ($size_one, $2)"
    return 1
  fi
  if ! key_two=$(echo "$objects" | jq -r '.Contents[1].Key' 2>&1); then
    log 2 "error obtaining key two: $key_two"
    return 1
  fi
  if [[ $key_two != "$3" ]]; then
    log 2 "Object two mismatch ($key_two, $3)"
    return 1
  fi
  if ! size_two=$(echo "$objects" | jq '.Contents[1].Size' 2>&1); then
    log 2 "error obtaining size two: $size_two"
    return 1
  fi
  if [[ $size_two -ne "$4" ]]; then
    log 2 "Object two size mismatch ($size_two, $4)"
    return 1
  fi
}

list_check_objects_v2() {
  if ! check_param_count "list_check_objects_v2" "bucket, expected key one, expected size one, expected key two, expected size two" 5 $#; then
    return 1
  fi
  if ! list_objects_v2 "$1"; then
    log 2 "error listing objects (s3api, v1)"
    return 1
  fi
  if ! check_listed_objects "$2" "$3" "$4" "$5"; then
    log 2 "error checking listed objects"
    return 1
  fi
  return 0
}

list_check_objects_rest() {
  if ! check_param_count "list_check_objects_rest" "bucket" 1 $#; then
    return 1
  fi
  list_objects "rest" "$1"
  object_found=false
  # shellcheck disable=SC2154
  for object in "${object_array[@]}"; do
    log 5 "object: $object"
    if [[ $object == "$test_file" ]]; then
      object_found=true
      break
    fi
  done
  if [[ $object_found == "false" ]]; then
    log 2 "object not found"
    return 1
  fi
  return 0
}

list_check_objects_common() {
  if ! check_param_count "list_check_objects_common" "client, bucket, object one, object two" 4 $#; then
    return 1
  fi
  if ! list_objects "$1" "$2"; then
    log 2 "error listing objects"
    return 1
  fi
  local object_one_found=false
  local object_two_found=false
  # shellcheck disable=SC2154
  for object in "${object_array[@]}"; do
    if [ "$object" == "$3" ] || [ "$object" == "s3://$2/$3" ]; then
      object_one_found=true
    elif [ "$object" == "$4" ] || [ "$object" == "s3://$2/$4" ]; then
      object_two_found=true
    fi
  done

  if [ $object_one_found != true ] || [ $object_two_found != true ]; then
    log 2 "$3 and/or $4 not listed (all objects: ${object_array[*]})"
    return 1
  fi
  return 0
}

list_objects_check_file_count() {
  if ! check_param_count "list_objects_check_file_count" "client, bucket, count" 3 $#; then
    return 1
  fi
  if ! list_objects "$1" "$2"; then
    log 2 "error listing objects"
    return 1
  fi
  if [[ $LOG_LEVEL -ge 5 ]]; then
    log 5 "Array: ${object_array[*]}"
  fi
  local file_count="${#object_array[@]}"
  if [[ $file_count != "$3" ]]; then
    log 2 "file count should be $3, is $file_count"
    return 1
  fi
  return 0
}

check_object_listing_with_prefixes() {
  if ! check_param_count "check_object_listing_with_prefixes" "bucket, folder name, object name" 3 $#; then
    return 1
  fi
  if ! list_objects_s3api_v1 "$BUCKET_ONE_NAME" "/"; then
    log 2 "error listing objects with delimiter '/'"
    return 1
  fi
  if ! prefix=$(echo "${objects[@]}" | jq -r ".CommonPrefixes[0].Prefix" 2>&1); then
    log 2 "error getting object prefix from object list: $prefix"
    return 1
  fi
  if [[ $prefix != "$2/" ]]; then
    log 2 "prefix doesn't match (expected $2, actual $prefix/)"
    return 1
  fi
  if ! list_objects_s3api_v1 "$BUCKET_ONE_NAME" "#"; then
    log 2 "error listing objects with delimiter '#"
    return 1
  fi
  if ! key=$(echo "${objects[@]}" | jq -r ".Contents[0].Key" 2>&1); then
    log 2 "error getting key from object list: $key"
    return 1
  fi
  if [[ $key != "$2/$3" ]]; then
    log 2 "key doesn't match (expected $key, actual $2/$3)"
    return 1
  fi
  return 0
}

list_objects_with_user_rest_verify_access_denied() {
  if ! check_param_count "list_objects_with_user_rest_verify_access_denied" "bucket, username, password" 3 $#; then
    return 1
  fi
  if ! result=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/objects.txt" ./tests/rest_scripts/list_objects.sh); then
    log 2 "error attempting to list objects: $result"
    return 1
  fi
  if [ "$result" != "403" ]; then
    log 2 "expected response code of '403', was '$result'"
    return 1
  fi
  error_message="$(cat "$TEST_FILE_FOLDER/objects.txt")"
  if [[ "$error_message" != *"Access Denied"* ]]; then
    log 2 "unexpected error message: $error_message"
    return 1
  fi
  return 0
}

list_objects_with_user_rest_verify_success() {
  if ! check_param_count "list_objects_with_user_rest_verify_success" "bucket, username, password, expected object" 4 $#; then
    return 1
  fi
  if ! result=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/objects.txt" ./tests/rest_scripts/list_objects.sh); then
    log 2 "error attempting to list objects: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' (error: $(cat "$TEST_FILE_FOLDER/objects.txt"))"
    return 1
  fi
  if ! key=$(xmllint --xpath '//*[local-name()="Key"]/text()' "$TEST_FILE_FOLDER/objects.txt" 2>&1); then
    log 2 "error getting object key: $key"
    return 1
  fi
  if [ "$key" != "$4" ]; then
    log 2 "expected '$4', was '$key'"
    return 1
  fi
  return 0
}

list_objects_check_params_get_token() {
  if ! check_param_count "list_objects_check_params_get_token" "bucket, files, version two" 4 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" VERSION_TWO="$4" MAX_KEYS=1 OUTPUT_FILE="$TEST_FILE_FOLDER/objects.txt" ./tests/rest_scripts/list_objects.sh); then
    log 2 "error attempting to get bucket ACL response: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200' was '$result' ($(cat "$TEST_FILE_FOLDER/objects.txt"))"
    return 1
  fi
  log 5 "objects: $(cat "$TEST_FILE_FOLDER/objects.txt")"
  if ! list_bucket_result=$(xmllint --xpath '//*[local-name()="ListBucketResult"]' "$TEST_FILE_FOLDER/objects.txt" 2>&1); then
    log 2 "error getting list bucket result: $list_bucket_result"
    return 1
  fi
  echo -n "$list_bucket_result" > "$TEST_FILE_FOLDER/list_bucket_result.txt"
  if ! check_xml_element "$TEST_FILE_FOLDER/list_bucket_result.txt" "$2" "Key"; then
    log 2 "key mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/list_bucket_result.txt" "1" "MaxKeys"; then
    log 2 "max keys mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/list_bucket_result.txt" "1" "KeyCount"; then
    log 2 "key count mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/list_bucket_result.txt" "true" "IsTruncated"; then
    log 2 "key count mismatch"
    return 1
  fi
  if ! continuation_token=$(xmllint --xpath '//*[local-name()="NextContinuationToken"]/text()' <(echo "$list_bucket_result") 2>&1); then
    log 2 "error getting next continuation token: $continuation_token"
    return 1
  fi
  echo "$continuation_token"
  return 0
}

list_objects_check_continuation_error() {
  if ! check_param_count "list_objects_check_continuation_error" "bucket, continuation token" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" VERSION_TWO="TRUE" MAX_KEYS=1 CONTINUATION_TOKEN="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/objects.txt" ./tests/rest_scripts/list_objects.sh); then
    log 2 "error attempting to get bucket ACL response: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected result code of '400' was '$result'"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/objects.txt" "InvalidArgument" "Error" "Code"; then
    log 2 "invalid error code"
    return 1
  fi
}

list_objects_v1_check_nextmarker_empty() {
  if ! check_param_count "list_objects_v1_check_nextmarker_empty" "bucket" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" VERSION_TWO="FALSE" MAX_KEYS=1 OUTPUT_FILE="$TEST_FILE_FOLDER/objects.txt" ./tests/rest_scripts/list_objects.sh); then
    log 2 "error attempting to get bucket ACL response: $result"
    return 1
  fi
  log 5 "output: $(cat "$TEST_FILE_FOLDER/objects.txt")"
  if ! next_marker=$(xmllint --xpath '//*[local-name()="NextMarker"]' "$TEST_FILE_FOLDER/objects.txt" 2>&1); then
    if [[ "$next_marker" != *"XPath set is empty"* ]]; then
      log 2 "unexpected error: $next_marker"
      return 1
    fi
    return 0
  fi
  log 5 "next marker: $next_marker"
  marker_text=$(xmllint --xpath 'string(/NextMarker)' <(echo "$next_marker") 2>&1)
  log 5 "marker text: $marker_text"
  if [[ "$marker_text" != *"Document is empty"* ]]; then
    log 2 "NextMarker text should be empty, but is $marker_text"
    return 1
  fi
  return 0
}

get_delete_marker_and_verify_405() {
  if ! check_param_count "get_delete_marker_and_verify_405" "bucket, file name" 2 $#; then
    return 1
  fi
  if ! list_object_versions_rest "$1"; then
    log 2 "error listing REST object versions"
    return 1
  fi
  log 5 "versions: $(cat "$TEST_FILE_FOLDER/object_versions.txt")"

  if ! version_id=$(xmllint --xpath "//*[local-name()=\"DeleteMarker\"]/*[local-name()=\"VersionId\"]/text()" "$TEST_FILE_FOLDER/object_versions.txt" 2>&1); then
    log 2 "error getting XML value: $version_id"
    return 1
  fi
  log 5 "xml val: $version_id"

  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$2" VERSION_ID="$version_id" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $result"
    return 1
  fi
  if [ "$result" != "405" ]; then
    log 2 "expected '405', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}
