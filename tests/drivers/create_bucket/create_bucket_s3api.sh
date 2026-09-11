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

setup_multipart_upload_with_params() {
  if ! check_param_count "setup_multipart_upload_with_params" "bucket, key" 2 $#; then
    return 1
  fi
  local bucket="$1" key="$2"
  local os_name later_seconds now_epoch later_epoch later result

  os_name="$(uname)"
  if [ "$DIRECT" == "true" ]; then
    later_seconds="40"
  else
    later_seconds="20"
  fi

  now_epoch=$(date +%s)
  later_epoch=$((now_epoch + later_seconds))
  if [[ "$os_name" == "Darwin" ]]; then
    later=$(date -r "$later_epoch" -u +"%Y-%m-%dT%H:%M:%SZ")
  else
    later=$(date -u -d "@$later_epoch" +"%Y-%m-%dT%H:%M:%SZ")
  fi
  log 5 "later in function: $later"

  if ! result=$(dd if=/dev/urandom of="${TEST_FILE_FOLDER}/${key}" bs=20971520 count=1 2>&1); then
    log 2 "error creating large file: $result"
    return 1
  fi

  if ! setup_bucket_object_lock_enabled_v2 "$bucket"; then
    log 2 "error creating bucket: $bucket"
    return 1
  fi
  log 5 "later in function: $later"
  echo "$later"
  return 0
}
