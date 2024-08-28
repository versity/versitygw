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

complete_multipart_upload() {
  if [[ $# -ne 4 ]]; then
    log 2 "'complete multipart upload' command requires bucket, key, upload ID, parts list"
    return 1
  fi
  log 5 "complete multipart upload id: $3, parts: $4"
  record_command "complete-multipart-upload" "client:s3api"
  error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2" --upload-id "$3" --multipart-upload '{"Parts": '"$4"'}' 2>&1) || local completed=$?
  if [[ $completed -ne 0 ]]; then
    log 2 "error completing multipart upload: $error"
    return 1
  fi
  log 5 "complete multipart upload error: $error"
  return 0
}