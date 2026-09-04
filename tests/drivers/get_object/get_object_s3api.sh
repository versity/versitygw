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

run_and_verify_multipart_upload_with_valid_range() {
  if ! check_param_count "run_and_verify_multipart_upload_with_valid_range" "bucket, key, 5MB file" 3 $#; then
    return 1
  fi
  local bucket="$1" key="$2" large_file="$3"
  local range_max=$((5*1024*1024-1)) object_size

  if ! multipart_upload_from_bucket_range "$bucket" "$key" "$large_file" 4 "bytes=0-$range_max"; then
    log 2 "error with multipart upload"
    return 1
  fi
  if ! get_object "s3api" "$bucket" "${key}-copy" "${large_file}-copy"; then
    log 2 "error getting object"
    return 1
  fi
  if [[ $(uname) == 'Darwin' ]]; then
    object_size=$(stat -f%z "${large_file}-copy")
  else
    object_size=$(stat --format=%s "${large_file}-copy")
  fi
  if [[ object_size -ne $((range_max*4+4)) ]]; then
    log 2 "object size mismatch ($object_size, $((range_max*4+4)))"
    return 1
  fi
  return 0
}