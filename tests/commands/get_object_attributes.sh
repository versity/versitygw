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

get_object_attributes() {
  record_command "get-object-attributes" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "'get object attributes' command requires bucket, key"
    return 1
  fi
  attributes=$(send_command aws --no-verify-ssl s3api get-object-attributes --bucket "$1" --key "$2" --object-attributes "ObjectSize" 2>&1) || local get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting object attributes: $attributes"
    return 1
  fi
  attributes=$(echo "$attributes" | grep -v "InsecureRequestWarning")
  log 5 "$attributes"
  return 0
}