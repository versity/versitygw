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

select_object_content() {
  record_command "select-object-content" "client:s3api"
  if [[ $# -ne 7 ]]; then
    log 2 "'select object content' command requires bucket, key, expression, expression type, input serialization, output serialization, outfile"
    return 1
  fi
  error=$(send_command aws --no-verify-ssl s3api select-object-content \
    --bucket "$1" \
    --key "$2" \
    --expression "$3" \
    --expression-type "$4" \
    --input-serialization "$5" \
    --output-serialization "$6" "$7" 2>&1) || local select_result=$?
  if [[ $select_result -ne 0 ]]; then
    log 2 "error selecting object content: $error"
    return 1
  fi
  return 0
}