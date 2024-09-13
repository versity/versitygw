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
  if ! get_object_tagging "$1" "$2" "$3"; then
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
    if ! tag_set_key=$(echo "$tags" | jq -r '.TagSet[0].Key' 2>&1); then
      log 2 "error retrieving tag key: $tag_set_key"
      return 1
    fi
    if ! tag_set_value=$(echo "$tags" | jq -r '.TagSet[0].Value' 2>&1); then
      log 2 "error retrieving tag value: $tag_set_value"
      return 1
    fi
    if [[ $tag_set_key != "$4" ]]; then
      log 2 "key mismatch ($tag_set_key, $4)"
      return 1
    fi
    if [[ $tag_set_value != "$5" ]]; then
      log 2 "value mismatch ($tag_set_value, $5)"
      return 1
    fi
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    if [[ $tag_set_key != "$4" ]]; then
      log 2 "Key mismatch ($tag_set_key, $4)"
      return 1
    fi
    if [[ $tag_set_value != "$5" ]]; then
      log 2 "Value mismatch ($tag_set_value, $5)"
      return 1
    fi
  fi
  return 0
}
