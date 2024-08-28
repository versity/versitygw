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

upload_part() {
  if [ $# -ne 5 ]; then
    log 2 "upload multipart part function must have bucket, key, upload ID, file name, part number"
    return 1
  fi
  local etag_json
  record_command "upload-part" "client:s3api"
  if ! etag_json=$(aws --no-verify-ssl s3api upload-part --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --body "$4-$(($5-1))" 2>&1); then
    log 2 "Error uploading part $5: $etag_json"
    return 1
  fi
  if ! etag=$(echo "$etag_json" | grep -v "InsecureRequestWarning" | jq '.ETag' 2>&1); then
    log 2 "error obtaining etag: $etag"
    return 1
  fi
  export etag
}