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

# use mc tool to delete bucket and contents
# params:  bucket name
# return 0 for success, 1 for failure
delete_bucket_recursive_mc() {
  if [[ $# -ne 1 ]]; then
    log 2 "delete bucket recursive mc command requires bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(mc --insecure rm --recursive --force "$MC_ALIAS"/"$1" 2>&1) || exit_code="$?"
  if [[ $exit_code -ne 0 ]]; then
    log 2 "error deleting bucket contents: $error"
    return 1
  fi
  error=$(mc --insecure rb "$MC_ALIAS"/"$1" 2>&1) || exit_code="$?"
  if [[ $exit_code -ne 0 ]]; then
    log 2 "error deleting bucket: $error"
    return 1
  fi
  return 0
}
