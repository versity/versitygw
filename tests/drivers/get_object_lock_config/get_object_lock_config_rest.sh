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

check_object_lock_config() {
  log 6 "check_object_lock_config"
  if ! check_param_count "check_object_lock_config" "bucket" 1 $#; then
    return 1
  fi
  lock_config_exists=true
  if ! get_object_lock_configuration "rest" "$1"; then
    # shellcheck disable=SC2154
    if [[ "$get_object_lock_config_err" == *"does not exist"* ]]; then
      # shellcheck disable=SC2034
      lock_config_exists=false
    else
      log 2 "error getting object lock config"
      return 1
    fi
  fi
  return 0
}