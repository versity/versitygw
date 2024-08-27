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

get_check_object_retention() {
  if [ $# -ne 3 ]; then
    log 2 "'get_check_object_retention' requires bucket, file, expected retention date"
    return 1
  fi
  # shellcheck disable=SC2154
  if ! get_object_retention "$BUCKET_ONE_NAME" "$bucket_file"; then
    log 2 "failed to get object retention"
    return 1
  fi
  log 5 "RETENTION:  $retention"
  retention=$(echo "$retention" | grep -v "InsecureRequestWarning")
  if ! mode=$(echo "$retention" | jq -r ".Retention.Mode" 2>&1); then
    log 2 "error getting retention mode: $mode"
    return 1
  fi
  if ! retain_until_date=$(echo "$retention" | jq -r ".Retention.RetainUntilDate" 2>&1); then
    log 2 "error getting retain until date: $retain_until_date"
    return 1
  fi
  if [[ $mode != "GOVERNANCE" ]]; then
    log 2 "retention mode should be governance, is $mode"
    return 1
  fi
  if [[ $retain_until_date != "$3"* ]]; then
    log 2 "retain until date should be $3, is $retain_until_date"
    return 1
  fi
  return 0
}