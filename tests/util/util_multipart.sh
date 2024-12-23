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

multipart_upload_from_bucket() {
  if [ $# -ne 4 ]; then
    log 2 "multipart upload from bucket command missing bucket, copy source, key, and/or part count"
    return 1
  fi

  if ! split_file "$3" "$4"; then
    log 2 "error splitting file"
    return 1
  fi

  for ((i=0;i<$4;i++)) {
    log 5 "key: $3"
    if ! put_object "s3api" "$3-$i" "$1" "$2-$i"; then
      log 2 "error copying object"
      return 1
    fi
  }

  if ! create_multipart_upload "$1" "$2-copy"; then
    log 2 "error running first multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    # shellcheck disable=SC2154
    if ! upload_part_copy "$1" "$2-copy" "$upload_id" "$2" "$i"; then
      log 2 "error uploading part $i"
      return 1
    fi
    # shellcheck disable=SC2154
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  if ! error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}' 2>&1); then
    log 2 "Error completing upload: $error"
    return 1
  fi
  return 0
}

multipart_upload_from_bucket_range() {
  if [ $# -ne 5 ]; then
    log 2 "multipart upload from bucket with range command requires bucket, copy source, key, part count, and range"
    return 1
  fi
  if ! split_file "$3" "$4"; then
    log 2 "error splitting file"
    return 1
  fi
  for ((i=0;i<$4;i++)) {
    log 5 "key: $3, file info: $(ls -l "$3"-"$i")"
    if ! put_object "s3api" "$3-$i" "$1" "$2-$i"; then
      log 2 "error copying object"
      return 1
    fi
  }

  if ! create_multipart_upload "$1" "$2-copy"; then
    log 2 "error running first multpart upload"
    return 1
  fi
  parts="["
  for ((i = 1; i <= $4; i++)); do
    if ! upload_part_copy_with_range "$1" "$2-copy" "$upload_id" "$2" "$i" "$5"; then
      # shellcheck disable=SC2154
      log 2 "error uploading part $i: $upload_part_copy_error"
      return 1
    fi
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
  if [ $# -lt 4 ]; then
    log 2 "multipart upload custom command missing bucket, key, file, part count, and/or optional additional params"
    return 1
  fi

  # shellcheck disable=SC2086 disable=SC2048
  if ! multipart_upload_before_completion_custom "$1" "$2" "$3" "$4" ${*:5}; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  log 5 "upload ID: $upload_id, parts: $parts"
  if ! complete_multipart_upload "$1" "$2" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

multipart_upload() {
  if [ $# -ne 4 ]; then
    log 2 "multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  if ! multipart_upload_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  if ! complete_multipart_upload "$1" "$2" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

# perform a multi-part upload
# params:  bucket, key, source file location, number of parts
# return 0 for success, 1 for failure
multipart_upload_with_params() {
  if [ $# -ne 10 ]; then
    log 2 "multipart upload command requires bucket, key, file, part count, content type, metadata, hold status, lock mode, retain until date, tagging"
    return 1
  fi
  log 5 "1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: ${10}"

  if ! multipart_upload_before_completion_with_params "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi
  log 5 "Upload parts:  $parts"

  if ! complete_multipart_upload "$1" "$2" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}



run_and_verify_multipart_upload_with_valid_range() {
  if [ $# -ne 3 ]; then
    log 2 "'run_and_verify_multipart_upload_with_valid_range' requires bucket, key, 5MB file"
    return 1
  fi
  range_max=$((5*1024*1024-1))
  if ! multipart_upload_from_bucket_range "$1" "$2" "$3" 4 "bytes=0-$range_max"; then
    log 2 "error with multipart upload"
    return 1
  fi
  if ! get_object "s3api" "$1" "$2-copy" "$3-copy"; then
    log 2 "error getting object"
    return 1
  fi
  if [[ $(uname) == 'Darwin' ]]; then
    object_size=$(stat -f%z "$3-copy")
  else
    object_size=$(stat --format=%s "$3-copy")
  fi
  if [[ object_size -ne $((range_max*4+4)) ]]; then
    log 2 "object size mismatch ($object_size, $((range_max*4+4)))"
    return 1
  fi
  return 0
}
