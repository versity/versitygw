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

get_and_check_object_size() {
  if [ $# -ne 3 ]; then
    log 2 "'get_and_check_object_size' requires bucket, key, object size"
    return 1
  fi
  if ! get_object_attributes "$1" "$2"; then
    log 2 "failed to get object attributes"
    return 1
  fi
  # shellcheck disable=SC2154
  if ! has_object_size=$(echo "$attributes" | jq 'has("ObjectSize")' 2>&1); then
    log 2 "error checking for ObjectSize parameters: $has_object_size"
    return 1
  fi
  if [[ $has_object_size != "true" ]]; then
    log 2 "ObjectSize parameter missing: $attributes"
    return 1
  fi
  if ! object_size=$(echo "$attributes" | jq -r ".ObjectSize" 2>&1); then
    log 2 "error getting object size: $object_size"
    return 1
  fi
  if [[ $object_size != "$3" ]]; then
    log 2 "Incorrect object size: $object_size"
    return 1
  fi
  return 0
}

get_object_metadata_and_check_keys() {
  if [ $# -ne 4 ]; then
    log 2 "'get_object_metadata_and_check_keys' requires bucket, key, expected metadata key, value"
    return 1
  fi
  if ! get_object_metadata "s3api" "$1" "$2"; then
    log 2 "error getting object metadata"
    return 1
  fi
  # shellcheck disable=SC2154
  if ! key=$(echo "$metadata" | jq -r 'keys[]' 2>&1); then
    log 2 "error getting key from metadata: $key"
    return 1
  fi
  if ! value=$(echo "$metadata" | jq -r '.[]' 2>&1); then
    log 2 "error getting value from metadata: $value"
    return 1
  fi
  if [[ $key != "$3" ]]; then
    log 2 "keys doesn't match (expected '$3', actual '$key')"
    return 1
  fi
  if [[ $value != "$4" ]]; then
    log 2 "values doesn't match (expected '$4', actual '$value')"
    return 1
  fi
  return 0
}
