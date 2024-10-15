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

put_object_lock_configuration() {
  if [[ $# -ne 4 ]]; then
    log 2 "'put-object-lock-configuration' command requires bucket name, enabled, mode, period"
    return 1
  fi
  local config="{\"ObjectLockEnabled\": \"$2\", \"Rule\": {\"DefaultRetention\": {\"Mode\": \"$3\", \"Days\": $4}}}"
  if ! error=$(send_command aws --no-verify-ssl s3api put-object-lock-configuration --bucket "$1" --object-lock-configuration "$config" 2>&1); then
    log 2 "error putting object lock configuration: $error"
    return 1
  fi
  return 0
}

put_object_lock_configuration_disabled() {
  if [[ $# -ne 1 ]]; then
    log 2 "'put-object-lock-configuration' disable command requires bucket name"
    return 1
  fi
  local config="{\"ObjectLockEnabled\": \"Enabled\"}"
  if ! error=$(send_command aws --no-verify-ssl s3api put-object-lock-configuration --bucket "$1" --object-lock-configuration "$config" 2>&1); then
    log 2 "error putting object lock configuration: $error"
    return 1
  fi
  return 0
}
