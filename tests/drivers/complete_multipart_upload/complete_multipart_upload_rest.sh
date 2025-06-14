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

complete_multipart_upload_with_checksum() {
  if ! check_param_count_v2 "bucket, key, file, upload ID, part count, checksum type, checksum algorithm" 7 $#; then
    return 1
  fi
  if ! parts_payload=$(upload_parts_rest_before_completion "$1" "$2" "$3" "$4" "$5" 2>&1); then
    log 2 "error uploading parts"
    return 1
  fi
  log 5 "parts payload: $parts_payload"
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$4" PARTS="$parts_payload" CHECKSUM_TYPE="$6" CHECKSUM_ALGORITHM="$7" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/complete_multipart_upload.sh); then
    log 2 "error completing multipart upload"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}