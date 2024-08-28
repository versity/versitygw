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

put_bucket_versioning() {
  record_command "put-bucket-versioning" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "put bucket versioning command requires command type, bucket name, 'Enabled' or 'Suspended'"
    return 1
  fi
  local put_result=0
  if [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api put-bucket-versioning --bucket "$2" --versioning-configuration "{ \"Status\": \"$3\"}" 2>&1) || put_result=$?
  fi
  if [[ $put_result -ne 0 ]]; then
    log 2 "error putting bucket versioning: $error"
    return 1
  fi
  return 0
}