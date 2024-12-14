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

delete_object_tagging() {
  record_command "delete-object-tagging" "client:$1"
  if [[ $# -ne 3 ]]; then
    log 2 "delete object tagging command missing command type, bucket, key"
    return 1
  fi
  delete_result=0
  if [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api delete-object-tagging --bucket "$2" --key "$3" 2>&1) || delete_result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(send_command mc --insecure tag remove "$MC_ALIAS/$2/$3") || delete_result=$?
  elif [ "$1" == 'rest' ]; then
    delete_object_tagging_rest "$2" "$3" || delete_result=$?
  else
    log 2 "delete-object-tagging command not implemented for '$1'"
    return 1
  fi
  if [[ $delete_result -ne 0 ]]; then
    log 2 "error deleting object tagging: $error"
    return 1
  fi
  return 0
}

delete_object_tagging_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'delete_object_tagging' requires bucket, key"
    return 1
  fi
  if ! result=$(BUCKET_NAME="$1" OBJECT_KEY="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/delete_object_tagging.sh); then
    log 2 "error sending delete object tagging REST command: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    log 2 "delete-object-tagging returned code $result (response: $(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  return 0
}
