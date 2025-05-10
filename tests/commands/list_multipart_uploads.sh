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

list_multipart_uploads() {
  record_command "list-multipart-uploads" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "'list multipart uploads' command requires bucket name"
    return 1
  fi
  if ! uploads=$(send_command aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1); then
    log 2 "error listing uploads: $uploads"
    return 1
  fi
}

list_multipart_uploads_rest() {
  record_command "list_multipart_uploads_rest" "client:rest"
  if ! check_param_count "list_multipart_upload_rest" "bucket" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/uploads.txt" ./tests/rest_scripts/list_multipart_uploads.sh 2>&1); then
    log 2 "error listing multipart uploads: $result"
    return 1
  fi
  uploads=$(cat "$TEST_FILE_FOLDER/uploads.txt")
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($uploads)"
    return 1
  fi
  return 0
}

list_multipart_uploads_with_user() {
  record_command "list-multipart-uploads" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'list multipart uploads' command requires bucket name, username, password"
    return 1
  fi
  if ! uploads=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" send_command aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1); then
    log 2 "error listing uploads: $uploads"
    # shellcheck disable=SC2034
    list_multipart_uploads_error=$uploads
    return 1
  fi
}