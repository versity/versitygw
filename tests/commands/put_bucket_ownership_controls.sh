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
  log 6 "put_bucket_ownership_controls"
  record_command "put-bucket-ownership-controls" "client:s3api"
  assert [ $# -eq 2 ]
  run aws --no-verify-ssl s3api put-bucket-ownership-controls --bucket "$1" --ownership-controls="Rules=[{ObjectOwnership=$2}]"
  # shellcheck disable=SC2154
  assert_success "error putting bucket ownership controls: $output"
}