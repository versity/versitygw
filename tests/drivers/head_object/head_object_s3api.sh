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

get_and_verify_metadata_value() {
  if ! check_param_count_v2 "data file, expected metadata key, expected metadata val" 3 $#; then
    return 1
  fi
  local data_file="$1" expected_metadata_key="$2" expected_metadata_val="$3"
  local response value

  if ! response=$(jq -r "$expected_metadata_key" - <<< "$data_file" 2>&1); then
    log 2 "error retrieving content type: $response"
    return 1
  fi
  value="$response"
  if [[ "$value" != "$expected_metadata_val" ]]; then
    log 2 "'$expected_metadata_key' mismatch (expected '$expected_metadata_val', actual '$value')"
    return 1
  fi
  return 0
}

get_and_verify_metadata() {
  if ! check_param_count_v2 "bucket file, expected content type, expected metadata key, expected metadata val, expected hold status, expected retention mode, expected retention date" 7 $#; then
    return 1
  fi
  local bucket_file="$1"
  local expected_content_type="$2"
  local expected_metadata_key="$3"
  local expected_metadata_val="$4"
  local expected_hold_status="$5"
  local expected_retention_mode="$6"
  local expected_retention_date="$7"

  if ! head_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file"; then
    log 2 "error retrieving metadata"
    return 1
  fi
  # shellcheck disable=SC2154
  raw_metadata=$(echo "$metadata" | grep -v "InsecureRequestWarning")
  log 5 "raw metadata: $raw_metadata"

  if ! get_and_verify_metadata_value "$raw_metadata" ".ContentType" "$expected_content_type"; then
    log 2 "error verifying .ContentType"
    return 1
  fi
  if ! get_and_verify_metadata_value "$raw_metadata" ".Metadata.${expected_metadata_key}" "$expected_metadata_val"; then
    log 2 "error verifying .Metadata.${expected_metadata_key}"
    return 1
  fi
  if ! get_and_verify_metadata_value "$raw_metadata" ".ObjectLockLegalHoldStatus" "$expected_hold_status"; then
    log 2 "error verifying .ObjectLockLegalHoldStatus"
    return 1
  fi
  if ! get_and_verify_metadata_value "$raw_metadata" ".ObjectLockMode" "$expected_retention_mode"; then
    log 2 "error verifying .ObjectLockLegalHoldStatus"
    return 1
  fi
  if ! get_and_verify_metadata_value "$raw_metadata" ".ObjectLockRetainUntilDate" "$expected_retention_date"; then
    log 2 "error verifying .ObjectLockRetainUntilDate"
    return 1
  fi
  return 0
}
