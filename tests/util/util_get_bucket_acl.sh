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

get_bucket_acl_and_check_owner() {
  if [ $# -ne 2 ]; then
    log 2 "'get_acl_and_check_owner' requires client, bucket name"
    return 1
  fi
  if ! get_bucket_acl "$1" "$2"; then
    log 2 "error getting bucket acl"
    return 1
  fi

  # shellcheck disable=SC2154
  log 5 "ACL: $acl"
  id=$(echo "$acl" | jq -r '.Owner.ID')
  [[ $id == "$AWS_ACCESS_KEY_ID" ]] || fail "Acl mismatch"
}