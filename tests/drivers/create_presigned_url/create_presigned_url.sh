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

source ./tests/commands/create_presigned_url.sh

create_check_presigned_url() {
  if ! check_param_count_v2 "client, bucket, key, save location" 4 $#; then
    return 1
  fi
  local response presigned_url

  if ! response=$(create_presigned_url "$1" "$2" "$3" 2>&1); then
    log 2 "error creating presigned URL: $response"
    return 1
  fi
  presigned_url="$response"

  if ! response=$(curl -k -v "$presigned_url" -o "$4"); then
    log 2 "error downloading file with curl: $response"
    return 1
  fi
  return 0
}