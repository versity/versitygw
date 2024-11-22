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

source ./tests/commands/get_object_tagging.sh

# params:  username, password, bucket, expected key, expected value
# return 0 for success, 1 for failure
get_and_check_bucket_tags_with_user() {
  log 6 "get_and_check_bucket_tags"
  if [ $# -ne 5 ]; then
    log 2 "'get_and_check_bucket_tags' requires username, password, bucket, expected key, expected value"
    return 1
  fi
  if ! get_bucket_tagging_with_user "$1" "$2" "$3"; then
    log 2 "error retrieving bucket tagging"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "TAGS: $tags"
  if ! tag=$(echo "$tags" | jq -r ".TagSet[0]" 2>&1); then
    log 2 "error getting tag: $tag"
    return 1
  fi
  if ! key=$(echo "$tag" | jq -r ".Key" 2>&1); then
    log 2 "error getting key: $key"
    return 1
  fi
  if [ "$key" != "$4" ]; then
    log 2 "key mismatch ($key, $4)"
    return 1
  fi
  if ! value=$(echo "$tag" | jq -r ".Value" 2>&1); then
    log 2 "error getting value: $value"
    return 1
  fi
  if [ "$value" != "$5" ]; then
    log 2 "value mismatch ($value, $5)"
    return 1
  fi
  return 0
}

# params:  bucket, expected tag key, expected tag value
# fail on error
get_and_check_bucket_tags() {
  if [ $# -ne 3 ]; then
    log 2 "'get_and_check_bucket_tags' requires bucket, expected tag key, expected tag value"
    return 1
  fi
  if ! get_and_check_bucket_tags_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2" "$3"; then
    log 2 "error getting and checking bucket tags with user"
    return 1
  fi
  return 0
}

verify_no_bucket_tags() {
  if [ $# -ne 2 ]; then
    log 2 "'verify_no_bucket_tags' requires bucket name"
    return 1
  fi
  if ! get_bucket_tagging "$1" "$2"; then
    log 2 "error retrieving bucket tagging"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$tags" != "" ]]; then
    log 2 "tags should be empty, but are: $tags"
    return 1
  fi
  return 0
}

verify_no_object_tags() {
  if [ $# -ne 3 ]; then
    log 2 "'verify_no_object_tags' requires client, bucket, object"
    return 1
  fi
  result=0
  get_object_tagging "$1" "$2" "$3" || result=$?
  if [ $result == 1 ]; then
    if [ "$1" == 'rest' ]; then
      return 0
    fi
    log 2 "error getting object tagging"
    return 1
  fi
  if [[ "$1" == 'aws' ]] || [ "$1" == 's3api' ]; then
    if ! tag_set=$(echo "$tags" | jq '.TagSet' 2>&1); then
      log 2 "error getting tag set: $tag_set"
      return 1
    fi
    if [[ $tag_set != "[]" ]] && [[ $tag_set != "" ]]; then
      log 2 "tags not empty ($tag_set)"
      return 1
    fi
  elif [[ $tags != *"No tags found"* ]] && [[ $tags != "" ]]; then
    log 2 "tags not empty (tags: $tags)"
    return 1
  fi
  return 0
}

check_verify_object_tags() {
  if [ $# -ne 5 ]; then
    log 2 "'check_verify_object_tags' requires client, bucket, key, expected tag key, expected tag value"
    return 1
  fi
  if ! get_object_tagging "$1" "$2" "$3"; then
    log 2 "error getting object tags"
    return 1
  fi
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    if ! parse_object_tags_s3api; then
      log 2 "error parsing object tags"
      return 1
    fi
  elif [ "$1" == 'rest' ]; then
    if ! parse_object_tags_rest; then
      log 2 "error parsing object tags"
      return 1
    fi
  elif [[ $1 == 'mc' ]]; then
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
  else
    log 2 "unrecognized client for check_verify_object_tags: $1"
    return 1
  fi
  if [[ $tag_set_key != "$4" ]]; then
    log 2 "Key mismatch ($tag_set_key, $4)"
    return 1
  fi
  if [[ $tag_set_value != "$5" ]]; then
    log 2 "Value mismatch ($tag_set_value, $5)"
    return 1
  fi
  return 0
}

parse_object_tags_s3api() {
  if ! tag_set_key=$(echo "$tags" | jq -r '.TagSet[0].Key' 2>&1); then
    log 2 "error retrieving tag key: $tag_set_key"
    return 1
  fi
  if ! tag_set_value=$(echo "$tags" | jq -r '.TagSet[0].Value' 2>&1); then
    log 2 "error retrieving tag value: $tag_set_value"
    return 1
  fi
  return 0
}

parse_object_tags_rest() {
  if ! tag_set_key=$(xmllint --xpath '//*[local-name()="Key"]/text()' "$TEST_FILE_FOLDER/object_tags.txt" 2>&1); then
    log 2 "error getting key: $tag_set_key"
    return 1
  fi
  if ! tag_set_value=$(xmllint --xpath '//*[local-name()="Value"]/text()' "$TEST_FILE_FOLDER/object_tags.txt" 2>&1); then
    log 2 "error getting value: $value"
    return 1
  fi
  return 0
}

check_tags_empty() {
  if [[ $# -ne 1 ]]; then
    log 2 "check tags empty requires command type"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    if [[ $tags == "" ]]; then
      return 0
    fi
    tag_set=$(echo "$tags" | jq '.TagSet')
    if [[ $tag_set != "[]" ]]; then
      log 2 "error:  tags not empty: $tags"
      return 1
    fi
  else
    if [[ $tags != "" ]] && [[ $tags != *"No tags found"* ]]; then
      log 2 "Error:  tags not empty: $tags"
      return 1
    fi
  fi
  return 0
}

check_object_tags_empty() {
  if [[ $# -ne 3 ]]; then
    log 2 "bucket tags empty check requires command type, bucket, and key"
    return 2
  fi
  if ! get_object_tagging "$1" "$2" "$3"; then
    log 2 "failed to get tags"
    return 2
  fi
  check_tags_empty "$1" || local check_result=$?
  # shellcheck disable=SC2086
  return $check_result
}

check_bucket_tags_empty() {
  if [[ $# -ne 2 ]]; then
    log 2 "bucket tags empty check requires command type, bucket"
    return 2
  fi
  if ! get_bucket_tagging "$1" "$2"; then
    log 2 "failed to get tags"
    return 2
  fi
  check_tags_empty "$1" || local check_result=$?
  # shellcheck disable=SC2086
  return $check_result
}

get_and_verify_object_tags() {
  if [[ $# -ne 5 ]]; then
    log 2 "get and verify object tags missing command type, bucket, key, tag key, tag value"
    return 1
  fi
  get_object_tagging "$1" "$2" "$3" || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "failed to get tags"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    tag_set_key=$(echo "$tags" | jq '.TagSet[0].Key')
    tag_set_value=$(echo "$tags" | jq '.TagSet[0].Value')
    if [[ $tag_set_key != '"'$4'"' ]]; then
      log 2 "Key mismatch ($tag_set_key, \"$4\")"
      return 1
    fi
    if [[ $tag_set_value != '"'$5'"' ]]; then
      log 2 "Value mismatch ($tag_set_value, \"$5\")"
      return 1
    fi
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    [[ $tag_set_key == "$4" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$5" ]] || fail "Value mismatch"
  fi
  return 0
}

verify_no_bucket_tags_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'verify_no_bucket_tags_rest' requires bucket name"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/bucket_tagging.txt" ./tests/rest_scripts/get_bucket_tagging.sh); then
    log 2 "error listing bucket tags: $result"
    return 1
  fi
  if [ "$result" != "404" ]; then
    log 2 "expected response code of '404', was '$result' (error: $(cat "$TEST_FILE_FOLDER/bucket_tagging.txt"))"
    return 1
  fi
  return 0
}

add_verify_bucket_tags_rest() {
  if [ $# -ne 3 ]; then
    log 2 "'add_verify_bucket_tags_rest' requires bucket name, test key, test value"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" TAG_KEY="$2" TAG_VALUE="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_bucket_tagging.sh); then
    log 2 "error putting bucket tags: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    log 2 "expected response code of '204', was '$result' (error: $(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OUTPUT_FILE="$TEST_FILE_FOLDER/bucket_tagging.txt" ./tests/rest_scripts/get_bucket_tagging.sh); then
    log 2 "error listing bucket tags: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' (error: $(cat "$TEST_FILE_FOLDER/bucket_tagging.txt"))"
    return 1
  fi
  log 5 "tags: $(cat "$TEST_FILE_FOLDER/bucket_tagging.txt")"
  if ! key=$(xmllint --xpath '//*[local-name()="Key"]/text()' "$TEST_FILE_FOLDER/bucket_tagging.txt" 2>&1); then
    log 2 "error retrieving key: $key"
    return 1
  fi
  if [ "$key" != "$2" ]; then
    log 2 "key mismatch (expected '$2', actual '$key')"
    return 1
  fi
  if ! value=$(xmllint --xpath '//*[local-name()="Value"]/text()' "$TEST_FILE_FOLDER/bucket_tagging.txt" 2>&1); then
    log 2 "error retrieving value: $value"
    return 1
  fi
  if [ "$value" != "$3" ]; then
    log 2 "value mismatch (expected '$3', actual '$value')"
    return 1
  fi
  return 0
}
