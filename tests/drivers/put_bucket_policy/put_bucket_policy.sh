#!/usr/bin/env bats

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

put_and_check_for_malformed_policy() {
  if ! check_param_count "put_and_check_for_malformed_policy" "bucket, policy file" 2 $#; then
    return 1
  fi
  if put_bucket_policy "s3api" "$1" "$2"; then
    log 2 "put succeeded despite malformed policy"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$put_bucket_policy_error" != *"MalformedPolicy"*"invalid action"* ]]; then
    log 2 "invalid policy error: $put_bucket_policy_error"
    return 1
  fi
  return 0
}