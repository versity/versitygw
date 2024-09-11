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

create_upload_and_test_parts_listing() {
  if [ $# -ne 2 ]; then
    log 2 "'create_upload_and_test_parts_listing' requires test file, policy_file"
    return 1
  fi
  if ! create_multipart_upload_with_user "$BUCKET_ONE_NAME" "$1" "$USERNAME_ONE" "$PASSWORD_ONE"; then
    log 2 "error creating multipart upload with user"
    return 1
  fi

  # shellcheck disable=SC2154
  if list_parts_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$1" "$upload_id"; then
    log 2 "list parts with user succeeded despite lack of policy permissions"
    return 1
  fi

  if ! setup_policy_with_single_statement "$TEST_FILE_FOLDER/$2" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:ListMultipartUploadParts" "arn:aws:s3:::$BUCKET_ONE_NAME/*"; then
    log 2 "error setting up policy"
    return 1
  fi

  if ! put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$2"; then
    log 2 "error putting policy"
    return 1
  fi

  if ! list_parts_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$1" "$upload_id"; then
    log 2 "error listing parts after policy add"
    return 1
  fi
  return 0
}

start_multipart_upload_list_check_parts() {
  if [ $# -ne 3 ]; then
    log 2 "'start_multipart_upload_and_list_parts' requires bucket, key, original source"
    return 1
  fi
  if ! start_multipart_upload_and_list_parts "$1" "$2" "$3" 4; then
    log 2 "error starting upload"
    return 1
  fi

  declare -a parts_map
  # shellcheck disable=SC2154
  log 5 "parts: $parts"
  for i in {0..3}; do
    if ! parse_parts_and_etags "$i"; then
      log 2 "error parsing part $i"
      return 1
    fi
  done
  if [[ ${#parts_map[@]} -eq 0 ]]; then
    log 2 "error loading multipart upload parts to check"
    return 1
  fi

  for i in {0..3}; do
    if ! compare_parts_to_listed_parts "$i"; then
      log 2 "error comparing parts to listed parts"
      return 1
    fi
  done
  return 0
}

parse_parts_and_etags() {
  if [ $# -ne 1 ]; then
    log 2 "'parse_parts_and_etags' requires part id"
    return 1
  fi
  local part_number
  local etag
  # shellcheck disable=SC2154
  if ! part=$(echo "$parts" | grep -v "InsecureRequestWarning" | jq -r ".[$i]" 2>&1); then
    log 2 "error getting part: $part"
    return 1
  fi
  if ! part_number=$(echo "$part" | jq ".PartNumber" 2>&1); then
    log 2 "error parsing part number: $part_number"
    return 1
  fi
  if [[ $part_number == "" ]]; then
    log 2 "error:  blank part number"
    return 1
  fi
  if ! etag=$(echo "$part" | jq ".ETag" 2>&1); then
    log 2 "error parsing etag: $etag"
    return 1
  fi
  if [[ $etag == "" ]]; then
    log 2 "error:  blank etag"
    return 1
  fi
  # shellcheck disable=SC2004
  parts_map[$part_number]=$etag
}

compare_parts_to_listed_parts() {
  if [ $# -ne 1 ]; then
    log 2 "'compare_parts_to_listed_parts' requires part number"
    return 1
  fi
  local part_number
  local etag
  # shellcheck disable=SC2154
  if ! listed_part=$(echo "$listed_parts" | grep -v "InsecureRequestWarning" | jq -r ".Parts[$i]" 2>&1); then
    log 2 "error parsing listed part: $listed_part"
    return 1
  fi
  if ! part_number=$(echo "$listed_part" | jq ".PartNumber" 2>&1); then
    log 2 "error parsing listed part number: $part_number"
    return 1
  fi
  if ! etag=$(echo "$listed_part" | jq ".ETag" 2>&1); then
    log 2 "error getting listed etag: $etag"
    return 1
  fi
  if [[ ${parts_map[$part_number]} != "$etag" ]]; then
    log 2 "error:  etags don't match (part number: $part_number, etags ${parts_map[$part_number]},$etag)"
    return 1
  fi
}
