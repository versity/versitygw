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
source ./tests/drivers/get_object_tagging/get_object_tagging_rest.sh
source ./tests/drivers/get_object_tagging/get_object_tagging_s3api.sh
source ./tests/drivers/tags.sh

get_and_verify_object_tags() {
  if ! check_param_count_v2 "command type, bucket, key, tag key, tag value" 5 $#; then
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

verify_no_object_tags() {
  if ! check_param_count_v2 "command type, bucket, key" 3 $#; then
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
  if ! check_param_count_v2 "command type, bucket, key, tag key, tag value" 5 $#; then
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
    if ! parse_object_tags_rest "$TEST_FILE_FOLDER/object_tags.txt"; then
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

check_object_tags_empty() {
  if ! check_param_count_v2 "command type, bucket, key" 3 $#; then
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

