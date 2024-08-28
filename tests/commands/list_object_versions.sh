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

list_object_versions() {
  record_command "list-object-versions" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "'list object versions' command requires bucket name"
    return 1
  fi
  versions=$(aws --no-verify-ssl s3api list-object-versions --bucket "$1") || local list_result=$?
  if [[ $list_result -ne 0 ]]; then
    log 2 "error listing object versions: $versions"
    return 1
  fi
  return 0
}