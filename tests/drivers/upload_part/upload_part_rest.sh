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