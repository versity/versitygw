#!/usr/bin/env bash

# Copyright 2025 Versity Software
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

source ./tests/util/util_mc.sh
source ./tests/logger.sh

create_and_check_bucket_invalid_name() {
  if ! check_param_count_v2 "client" 1 $#; then
    return 1
  fi
  if ! create_bucket_invalid_name "$1"; then
    log 2 "error creating bucket with invalid name"
    return 1
  fi

  # shellcheck disable=SC2154
  if [[ "$bucket_create_error" != *"Invalid bucket name "* ]] && [[ "$bucket_create_error" != *"Bucket name cannot"* ]]; then
    log 2 "unexpected error:  $bucket_create_error"
    return 1
  fi
  return 0
}
