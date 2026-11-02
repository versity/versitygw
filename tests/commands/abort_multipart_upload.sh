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

abort_multipart_upload() {
  if [ $# -ne 3 ]; then
    log 2 "'abort multipart upload' command requires bucket, key, upload ID"
    return 1
  fi
  if ! error=$(send_command aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" --key "$2" --upload-id "$3" 2>&1); then
    log 2 "Error aborting upload: $error"
    return 1
  fi
  return 0
}

abort_multipart_upload_rest() {
  if ! check_param_count "abort_multipart_upload_rest" "bucket, key, upload ID" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/abort_multipart_upload.sh); then
    log 2 "error aborting multipart upload: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    log 2 "expected '204' response, actual was '$result' (error: $(cat "$TEST_FILE_FOLDER"/result.txt)"
    return 1
  fi
  return 0
}

abort_multipart_upload_with_user() {
  if ! check_param_count_v2 "bucket, key, upload ID, username, password" 5 $#; then
    return 1
  fi
  local bucket="$1" key="$2" upload_id="$3" username="$4" password="$5"
  local response

  if ! response=$(AWS_ACCESS_KEY_ID="$username" AWS_SECRET_ACCESS_KEY="$password" send_command aws \
      --no-verify-ssl s3api abort-multipart-upload --bucket "$bucket" --key "$key" --upload-id "$upload_id" 2>&1); then
    log 2 "Error aborting upload: $response"
    printf '%s\n' "$response"
    return 1
  fi
  return 0
}
