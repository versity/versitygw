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

# params:  client, bucket
# export 'tags' on success, return 1 for error
get_bucket_tagging() {
  log 6 "get_bucket_tagging"
  assert [ $# -eq 2 ]
  record_command "get-bucket-tagging" "client:$1"
  local result
  if [[ $1 == 's3api' ]]; then
    tags=$(send_command aws --no-verify-ssl s3api get-bucket-tagging --bucket "$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(send_command mc --insecure tag list "$MC_ALIAS"/"$2" 2>&1) || result=$?
  else
    fail "invalid command type $1"
  fi
  log 5 "Tags: $tags"
  tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  if [[ $result -ne 0 ]]; then
    if [[ $tags =~ "No tags found" ]] || [[ $tags =~ "The TagSet does not exist" ]]; then
      export tags=
      return 0
    fi
    log 2 "error getting bucket tags: $tags"
    return 1
  fi
  export tags
}

get_bucket_tagging_with_user() {
  log 6 "get_bucket_tagging_with_user"
  if [ $# -ne 3 ]; then
    log 2 "'get_bucket_tagging_with_user' command requires ID, key, bucket"
    return 1
  fi
  record_command "get-bucket-tagging" "client:s3api"
  local result
  if ! tags=$(AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" send_command aws --no-verify-ssl s3api get-bucket-tagging --bucket "$3" 2>&1); then
    log 5 "tags error: $tags"
    if [[ $tags =~ "No tags found" ]] || [[ $tags =~ "The TagSet does not exist" ]]; then
      export tags=
      return 0
    fi
    fail "unrecognized error getting bucket tagging with user: $tags"
    return 1
  fi
  log 5 "raw tags data: $tags"
  tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  log 5 "modified tags data: $tags"
  return 0
}
