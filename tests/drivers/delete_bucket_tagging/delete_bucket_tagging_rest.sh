#!/usr/bin/env bats

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

delete_tags_and_verify_deletion() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  if ! send_rest_go_command "204" \
    "-method" "DELETE" "-bucketName" "$1" "-query" "tagging="; then
    log 2 "error sending tag deletion command"
    return 1
  fi
  if ! verify_no_bucket_tags_rest "$1"; then
    log 2 "error verifying no bucket tags"
    return 1
  fi
  return 0
}
