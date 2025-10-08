#!/usr/bin/env bash

# Copyright 2025 Versity Software
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

bucket_is_accessible() {
  if ! check_param_count "bucket_is_accessible" "bucket" 1 $#; then
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws --no-verify-ssl s3api head-bucket --bucket "$1" 2>&1) || exit_code="$?"
  if [ $exit_code -eq 0 ]; then
    return 0
  fi
  if [[ "$error" == *"500"* ]]; then
    return 1
  fi
  log 2 "Error checking bucket accessibility: $error"
  return 2
}

check_for_empty_region() {
  if ! check_param_count "check_for_empty_region" "bucket" 1 $#; then
    return 2
  fi
  if ! head_bucket "s3api" "$BUCKET_ONE_NAME"; then
    log 2 "error getting bucket info"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "INFO:  $bucket_info"
  if ! region=$(echo "$bucket_info" | grep -v "InsecureRequestWarning" | jq -r ".BucketRegion" 2>&1); then
    log 2 "error getting region: $region"
    return 1
  fi
  if [[ $region == "" ]]; then
    log 2 "empty bucket region"
    return 1
  fi
  return 0
}
