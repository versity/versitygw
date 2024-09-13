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

get_object_tagging() {
  record_command "get-object-tagging" "client:$1"
  if [ $# -ne 3 ]; then
    log 2 "get object tag command missing command type, bucket, and/or key"
    return 1
  fi
  local result
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    tags=$(aws --no-verify-ssl s3api get-object-tagging --bucket "$2" --key "$3" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(mc --insecure tag list "$MC_ALIAS"/"$2"/"$3" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    if [[ "$tags" == *"NoSuchTagSet"* ]] || [[ "$tags" == *"No tags found"* ]]; then
      tags=
    else
      log 2 "error getting object tags: $tags"
      return 1
    fi
  else
    log 5 "$tags"
    tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  fi
  export tags
}