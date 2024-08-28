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

delete_objects() {
  record_command "delete-objects" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'delete-objects' command requires bucket name, two object keys"
    return 1
  fi
  if ! error=$(aws --no-verify-ssl s3api delete-objects --bucket "$1" --delete "{
      \"Objects\": [
        {\"Key\": \"$2\"},
        {\"Key\": \"$3\"}
      ]
    }" 2>&1); then
    log 2 "error deleting objects: $error"
    return 1
  fi
  return 0
}