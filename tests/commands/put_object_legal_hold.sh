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

put_object_legal_hold() {
  record_command "put-object-legal-hold" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'put object legal hold' command requires bucket, key, hold status ('ON' or 'OFF')"
    return 1
  fi
  if ! error=$(send_command aws --no-verify-ssl s3api put-object-legal-hold --bucket "$1" --key "$2" --legal-hold "{\"Status\": \"$3\"}" 2>&1); then
    log 2 "error putting object legal hold: $error"
    return 1
  fi
  return 0
}

put_object_legal_hold_version_id() {
  record_command "put-object-legal-hold" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "'put_object_legal_hold_version_id' command requires bucket, key, version ID, hold status ('ON' or 'OFF')"
    return 1
  fi
  local error=""
  if ! error=$(send_command aws --no-verify-ssl s3api put-object-legal-hold --bucket "$1" --key "$2" --version-id "$3" --legal-hold "{\"Status\": \"$4\"}" 2>&1); then
    log 2 "error putting object legal hold w/version ID: $error"
    return 1
  fi
  return 0
}
