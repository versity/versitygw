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

# check if bucket exists
# param:  bucket name
# return 0 for true, 1 for false, 2 for error
bucket_exists() {
  if [ $# -ne 2 ]; then
    log 2 "bucket_exists command requires client, bucket name"
    return 2
  fi
  local exists=0
  head_bucket "$1" "$2" || exists=$?
  # shellcheck disable=SC2181
  if [ $exists -eq 2 ]; then
    log 2 "unexpected error checking if bucket exists"
    return 2
  fi
  if [ $exists -eq 0 ]; then
    return 0
  fi
  return 1
}
