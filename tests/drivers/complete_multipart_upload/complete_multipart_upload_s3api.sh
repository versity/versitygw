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

multipart_upload_s3api_complete_from_bucket() {
  if ! check_param_count "multipart_upload_s3api_complete_from_bucket" "bucket, copy source, part count" 3 $#; then
    return 1
  fi
  local bucket="$1" copy_source="$2" part_count="$3"
  local parts i etag error

  parts="["
  for ((i = 1; i <= part_count; i++)); do
    # shellcheck disable=SC2154
    if ! upload_part_copy "$bucket" "${copy_source}-copy" "$upload_id" "$copy_source" "$i"; then
      log 2 "error uploading part $i"
      return 1
    fi
    # shellcheck disable=SC2154
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $part_count ]]; then
      parts+=","
    fi
  done
  parts+="]"

  if ! error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$bucket" --key "${copy_source}-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}' 2>&1); then
    log 2 "Error completing upload: $error"
    return 1
  fi
  return 0
}

multipart_upload_from_bucket() {
  if ! check_param_count "multipart_upload_from_bucket" "bucket, copy source, key, part count" 4 $#; then
    return 1
  fi
  local bucket="$1" copy_source="$2" key="$3" part_count="$4"
  local segments upload_id
  local -a segment_array

  if ! segments=$(split_file "$key" "$part_count" 2>&1); then
    log 2 "error splitting file"
    return 1
  fi
  read -r -a segment_array <<< "$segments"

  for ((i=0;i<part_count;i++)) {
    log 5 "key: '$key'"
    if ! put_object "s3api" "${segment_array[$i]}" "$bucket" "${copy_source}-$i"; then
      log 2 "error copying object"
      return 1
    fi
  }

  local response
  if ! response=$(create_multipart_upload_rest "$bucket" "${copy_source}-copy" "" "parse_upload_id" 2>&1); then
    log 2 "error running first multipart upload: $response"
    return 1
  fi
  upload_id="$response"

  if ! multipart_upload_s3api_complete_from_bucket "$bucket" "$copy_source" "$part_count"; then
    log 2 " error completing multipart upload from bucket"
    return 1
  fi
  return 0
}

multipart_upload_from_bucket_range() {
  if ! check_param_count "multipart_upload_from_bucket_range" "bucket, copy source, key, part count, range" 5 $#; then
    return 1
  fi
  local bucket="$1" copy_source="$2" key="$3" part_count="$4" range="$5"
  local segments parts
  local -a segment_array

  if ! segments=$(split_file "$key" "$part_count" 2>&1); then
    log 2 "error splitting file"
    return 1
  fi
  read -r -a segment_array <<< "$segments"

  for ((i=0;i<part_count;i++)) {
    log 5 "key: '$key', file info: '$(ls -l "${key}"-"$i")'"
    if ! put_object "s3api" "${segment_array[$i]}" "$bucket" "${copy_source}-$i"; then
      log 2 "error copying object"
      return 1
    fi
  }

  local response
  if ! response=$(create_multipart_upload_rest "$bucket" "${copy_source}-copy" "" "parse_upload_id" 2>&1); then
    log 2 "error running first multpart upload: $response"
    return 1
  fi
  upload_id="$response"

  parts="["
  for ((i = 1; i <= part_count; i++)); do
    if ! response=$(upload_part_copy_with_range "$bucket" "${copy_source}-copy" "$upload_id" "$copy_source" "$i" "$range" 2>&1); then
      # shellcheck disable=SC2154
      log 2 "error uploading part $i: '$response'"
      return 1
    fi
    etag="$response"
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"
  if ! error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}'); then
    log 2 "Error completing upload: $error"
    return 1
  fi
  return 0
}

multipart_upload_custom() {
  if ! check_param_count_gt "bucket, key, file, part count, optional additional parameters" 4 $$; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" part_count="$4" params=("${@:5}")

  # shellcheck disable=SC2086 disable=SC2048
  if ! multipart_upload_before_completion_custom "$bucket" "$key" "$file" "$part_count" "${params[@]}"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  log 5 "upload ID: $upload_id, parts: $parts"
  if ! complete_multipart_upload "$bucket" "$key" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

multipart_upload() {
  if ! check_param_count "multipart_upload" "bucket, key, file, part count" 4 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" part_count="$4"

  if ! multipart_upload_before_completion "$bucket" "$key" "$file" "$part_count"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  if ! complete_multipart_upload "$bucket" "$key" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

# perform a multi-part upload
# params:  bucket, key, source file location, number of parts
# return 0 for success, 1 for failure
multipart_upload_with_params() {
  if ! check_param_count "multipart_upload_with_params" "bucket, key, file, part count, content type, metadata, hold status, lock mode, retain until date, tagging" 10 $#; then
    return 1
  fi
  local bucket="$1"
  local key="$2"
  local file="$3"
  local part_count="$4"
  local content_type="$5"
  local metadata="$6"
  local hold_status="$7"
  local lock_mode="$8"
  local retain_until_date="$9"
  local tagging="${10}"

  if ! multipart_upload_before_completion_with_params "$bucket" "$key" "$file" "$part_count" "$content_type" \
      "$metadata" "$hold_status" "$lock_mode" "$retain_until_date" "$tagging"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi
  log 5 "Upload parts:  $parts"

  if ! complete_multipart_upload "$bucket" "$key" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}
