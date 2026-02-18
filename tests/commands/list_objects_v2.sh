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

# list objects in bucket, v2
# param:  bucket
# export objects on success, return 1 for failure
list_objects_v2() {
  if [ $# -ne 1 ]; then
    log 2 "list objects command missing bucket and/or path"
    return 1
  fi
  objects=$(send_command aws --no-verify-ssl s3api list-objects-v2 --bucket "$1") || local result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error listing objects: $objects"
    return 1
  fi
}

list_objects_v2_rest_callback() {
  if ! check_param_count_gt "bucket, expected response code, callback fn, params" 3 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "$2" "$3" "-bucketName" "$1" "-method" "GET" "-query" "list-type=2" "${@:4}"; then
    log 2 "error sending REST ListObjectsV2 command or parsing callback"
    return 1
  fi
  return 0
}