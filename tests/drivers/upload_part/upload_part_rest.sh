#!/usr/bin/env bats

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

upload_parts_rest_before_completion() {
  if ! check_param_count_v2 "bucket, key, file, upload ID, part count" 5 $#; then
    return 1
  fi
  if ! split_file "$3" "$5"; then
    log 2 "error splitting file"
    return 1
  fi
  local parts_payload=""
  for ((part=0;part<"$5";part++)); do
    part_number=$((part+1))
    if ! etag=$(upload_part_rest "$1" "$2" "$4" "$part_number" "$3-$part" 2>&1); then
      log 2 "error uploading part $part: $etag"
      return 1
    fi
    parts_payload+="<Part><ETag>$etag</ETag><PartNumber>$part_number</PartNumber></Part>"
  done
  echo "$parts_payload"
  return 0
}

upload_parts_rest_with_checksum_before_completion() {
  if ! check_param_count_v2 "bucket, key, file, upload ID, part count, algorithm" 6 $#; then
    return 1
  fi
  if ! split_file "$3" "$5"; then
    log 2 "error splitting file"
    return 1
  fi
  parts_payload=""
  checksums=()
  for ((part=0;part<"$5";part++)); do
    part_number=$((part+1))
    if ! upload_part_rest_with_checksum "$1" "$2" "$4" "$part_number" "$3-$part" "$6"; then
      log 2 "error uploading part $part"
      return 1
    fi
    checksums+=("$checksum")
    uppercase_checksum_algorithm=$(echo -n "$6" | tr '[:lower:]' '[:upper:]')
    parts_payload+="<Part><ETag>$etag</ETag><Checksum${uppercase_checksum_algorithm}>${checksum}</Checksum${uppercase_checksum_algorithm}><PartNumber>$part_number</PartNumber></Part>"
    log 5 "parts payload: $parts_payload"
  done
  log 5 "${checksums[*]}"
  return 0
}

perform_full_multipart_upload_with_checksum_before_completion() {
  if ! check_param_count_v2 "bucket, filename, checksum type, algorithm" 4 $#; then
    return 1
  fi
  if ! setup_bucket_and_large_file "$1" "$2"; then
    log 2 "error setting up bucket and large file"
    return 1
  fi
  if ! create_multipart_upload_rest_with_checksum_type_and_algorithm "$1" "$2" "$3" "$4"; then
    log 2 "error creating multipart upload"
    return 1
  fi
  lowercase_checksum_algorithm=$(echo -n "$4" | tr '[:upper:]' '[:lower:]')
  if ! upload_parts_rest_with_checksum_before_completion "$1" "$2" "$TEST_FILE_FOLDER/$2" "$upload_id" 2 "$lowercase_checksum_algorithm"; then
    log 2 "error uploading parts"
    return 1
  fi
}