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

# fail if unable to put bucket ownership controls
put_bucket_ownership_controls() {
  if [[ -n "$SKIP_BUCKET_OWNERSHIP_CONTROLS" ]]; then
    log 5 "Skipping get bucket ownership controls"
    return 0
  fi

  log 6 "put_bucket_ownership_controls"
  if [ $# -ne 2 ]; then
    log 2 "'put_bucket_ownership_controls' requires bucket name, rule"
    return 1
  fi
  record_command "put-bucket-ownership-controls" "client:s3api"
  if ! error=$(send_command aws --no-verify-ssl s3api put-bucket-ownership-controls --bucket "$1" --ownership-controls="Rules=[{ObjectOwnership=$2}]" 2>&1); then
    log 2 "error putting bucket ownership controls: $error"
    return 1
  fi
}