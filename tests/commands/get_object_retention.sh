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

get_object_retention() {
  record_command "get-object-retention" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "'get object retention' command requires bucket, key"
    return 1
  fi
  if ! retention=$(aws --no-verify-ssl s3api get-object-retention --bucket "$1" --key "$2" 2>&1); then
    log 2 "error getting object retention: $retention"
    get_object_retention_error=$retention
    export get_object_retention_error
    return 1
  fi
  return 0
}