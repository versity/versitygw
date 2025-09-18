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

source ./tests/commands/list_objects_v2.sh
source ./tests/drivers/xml.sh
source ./tests/util/util_legal_hold.sh

list_and_delete_objects() {
  log 6 "list_and_delete_objects"
  if ! check_param_count "list_and_delete_objects" "bucket" 1 $#; then
    return 1
  fi
  if ! list_objects_rest "$1" "parse_objects_list_rest"; then
    log 2 "error getting object list"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "objects: ${object_array[*]}"
  for object in "${object_array[@]}"; do
    if ! clear_object_in_bucket "$1" "$object"; then
      log 2 "error deleting object $object"
      return 1
    fi
  done

  if ! delete_old_versions_base64 "$1"; then
    log 2 "error deleting old version"
    return 1
  fi
  return 0
}

delete_old_versions_base64() {
  if ! check_param_count "delete_old_versions" "bucket" 1 $#; then
    return 1
  fi
  if ! list_object_versions "rest" "$1"; then
    log 2 "error listing object versions"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "versions: $versions"

  if ! parse_base64_versions_rest; then
    log 2 "error parsing version data"
    return 1
  fi

  log 5 "base64 versions: ${base64_pairs[*]}"
  for pair in "${base64_pairs[@]}"; do
    log 5 "pair: $pair"
    if ! delete_object_version_with_or_without_retention_base64 "$1" "$pair"; then
      log 2 "error deleting version with or without retention"
      return 1
    fi
  done
}

delete_object_version_with_or_without_retention_base64() {
  if ! check_param_count_v2 "bucket, key/value pair" 2 $#; then
    return 1
  fi
  IFS=":" read -ra key_and_id <<< "$2"
  log 5 "key and ID: ${key_and_id[*]}"
  if ! key=$(printf '%s' "${key_and_id[0]}" | base64 --decode 2>&1); then
    log 2 "error decoding key: $key"
    return 1
  fi
  if ! id=$(printf '%s' "${key_and_id[1]}" | base64 --decode 2>&1); then
    log 2 "error decoding ID: $id"
    return 1
  fi
  # shellcheck disable=SC2154
  if [ "$lock_config_exists" == "true" ]; then
    if ! check_remove_legal_hold_versions "$1" "$key" "$id"; then
      log 2 "error checking, removing legal hold versions"
      return 1
    fi
    if ! delete_object_version_rest_bypass_retention "$1" "$key" "$id"; then
      log 2 "error deleting object version, bypassing retention"
      return 1
    fi
  else
    if ! delete_object_version_rest "$1" "$key" "$id"; then
      log 2 "error deleting object version"
      return 1
    fi
  fi
  log 5 "successfully deleted version with key '$key', id '$id'"
  return 0
}
