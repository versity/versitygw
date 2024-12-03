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

head_object() {
  record_command "head-object" "client:$1"
  if [ $# -ne 3 ]; then
    log 2 "head-object missing command, bucket name, object name"
    return 2
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    metadata=$(send_command aws --no-verify-ssl s3api head-object --bucket "$2" --key "$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 's3cmd' ]]; then
    metadata=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info s3://"$2/$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 'mc' ]]; then
    metadata=$(send_command mc --insecure stat "$MC_ALIAS/$2/$3" 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 2
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$metadata" == *"404"* ]] || [[ "$metadata" == *"does not exist"* ]]; then
      log 5 "file doesn't exist ($metadata)"
      return 1
    else
      log 2 "error checking if object exists: $metadata"
      return 2
    fi
  fi
  return 0
}