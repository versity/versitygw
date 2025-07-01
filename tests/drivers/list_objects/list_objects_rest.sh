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

# param: bucket name
# return 0 for success, 1 for failure
list_and_delete_objects() {
  log 6 "list_and_delete_objects"
  if ! check_param_count "list_and_delete_objects" "bucket" 1 $#; then
    return 1
  fi
  if ! list_objects 'rest' "$1"; then
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

  if ! delete_old_versions "$1"; then
    log 2 "error deleting old version"
    return 1
  fi
  return 0
}
