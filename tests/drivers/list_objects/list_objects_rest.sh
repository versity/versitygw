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
  if ! list_objects_rest "$1" "parse_objects_list_rest" "$3"; then
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
