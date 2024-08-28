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

get_bucket_versioning() {
  record_command "get-bucket-versioning" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "put bucket versioning command requires command type, bucket name"
    return 1
  fi
  local get_result=0
  if [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api get-bucket-versioning --bucket "$2" 2>&1) || get_result=$?
  fi
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting bucket versioning: $error"
    return 1
  fi
  return 0
}