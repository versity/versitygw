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

get_and_verify_metadata() {
  if [ $# -ne 7 ]; then
    log 2 "'get_and_verify_metadata' requires bucket file, expected content type,
     expected metadata key, expected metadata val, expected hold status, expected retention mode, expected retention date"
    return 1
  fi
  if ! head_object "s3api" "$BUCKET_ONE_NAME" "$1"; then
    log 2 "error retrieving metadata"
    return 1
  fi
  # shellcheck disable=SC2154
  raw_metadata=$(echo "$metadata" | grep -v "InsecureRequestWarning")
  log 5 "raw metadata: $raw_metadata"

  if ! content_type=$(echo "$raw_metadata" | jq -r ".ContentType" 2>&1); then
    log 2 "error retrieving content type: $content_type"
    return 1
  fi
  if [[ $content_type != "$2" ]]; then
    log 2 "content type mismatch ($content_type, $2)"
    return 1
  fi
  log 5 "metadata key: $3"
  if ! meta_val=$(echo "$raw_metadata" | jq -r ".Metadata.$3" 2>&1); then
    log 2 "error retrieving metadata val: $meta_val"
    return 1
  fi
  if [[ $meta_val != "$4" ]]; then
    log 2 "metadata val mismatch ($meta_val, $4)"
    return 1
  fi
  if ! hold_status=$(echo "$raw_metadata" | jq -r ".ObjectLockLegalHoldStatus" 2>&1); then
    log 2 "error retrieving hold status: $hold_status"
    return 1
  fi
  if [[ $hold_status != "$5" ]]; then
    log 2 "hold status mismatch ($hold_status, $5)"
    return 1
  fi
  if ! retention_mode=$(echo "$raw_metadata" | jq -r ".ObjectLockMode" 2>&1); then
    log 2 "error retrieving retention mode: $retention_mode"
    return 1
  fi
  if [[ $retention_mode != "$6" ]]; then
    log 2 "retention mode mismatch ($retention_mode, $6)"
    return 1
  fi
  if ! retain_until_date=$(echo "$raw_metadata" | jq -r ".ObjectLockRetainUntilDate" 2>&1); then
    log 2 "error retrieving retain until date: $retain_until_date"
    return 1
  fi
  if [[ $retain_until_date != "$7"* ]]; then
    log 2"retention date mismatch ($retain_until_date, $7)"
    return 1
  fi
  return 0
}
