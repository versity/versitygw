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

put_object_tagging() {
  if [ $# -ne 5 ]; then
    log 2 "'put-object-tagging' command missing command type, object name, file, key, and/or value"
    return 1
  fi
  local error
  local result
  record_command "put-object-tagging" "client:$1"
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-object-tagging --bucket "$2" --key "$3" --tagging "TagSet=[{Key=$4,Value=$5}]" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure tag set "$MC_ALIAS"/"$2"/"$3" "$4=$5" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    log 2 "Error adding object tag: $error"
    return 1
  fi
  return 0
}