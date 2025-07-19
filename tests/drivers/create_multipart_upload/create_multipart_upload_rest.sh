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

parse_upload_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! upload_id=$(get_element_text "$1" "InitiateMultipartUploadResult" "UploadId"); then
    log 2 "error getting upload ID: $upload_id"
    return 1
  fi
  echo "$upload_id"
  return 0
}