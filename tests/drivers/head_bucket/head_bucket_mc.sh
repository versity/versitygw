#!/usr/bin/env bash

# Copyright 2026 Versity Software
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

bucket_info_contains_bucket() {
  if ! check_param_count_v2 "client, bucket" 2 $#; then
    return 1
  fi
  if ! head_bucket "mc" "$BUCKET_ONE_NAME"; then
    log 2 "error getting bucket info"
    return 1
  fi

  # shellcheck disable=SC2154
  if [[ "$bucket_info" != *"$BUCKET_ONE_NAME"* ]]; then
    return 1
  fi
  return 0
}
