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

source ./tests/util/util_users.sh

create_versitygw_acl_user_or_get_direct_user() {
  if [ $# -ne 2 ]; then
    log 2 "'create_versitygw_acl_user_or_get_direct_user' requires username, password"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    if [ -z "$AWS_CANONICAL_ID" ] || [ -z "$ACL_AWS_CANONICAL_ID" ] || [ -z "$ACL_AWS_ACCESS_KEY_ID" ] || [ -z "$ACL_AWS_SECRET_ACCESS_KEY" ]; then
      log 2 "direct ACL calls require the following env vars: AWS_CANONICAL_ID, ACL_AWS_CANONICAL_ID, ACL_AWS_ACCESS_KEY_ID, ACL_AWS_SECRET_ACCESS_KEY"
      return 1
    fi
    owner_canonical_id="$AWS_CANONICAL_ID"
    user_canonical_id="$ACL_AWS_CANONICAL_ID"
    username="$ACL_AWS_ACCESS_KEY_ID"
    password="$ACL_AWS_SECRET_ACCESS_KEY"
  else
    owner_canonical_id="$AWS_ACCESS_KEY_ID"
    if ! create_user_versitygw "$1" "$2" "user"; then
      log 2 "error creating versitygw user"
      return 1
    fi
    # shellcheck disable=SC2154
    user_canonical_id="$1"
    username="$1"
    # shellcheck disable=SC2154
    password="$2"
  fi
  echo "$owner_canonical_id"
  echo "$user_canonical_id"
  echo "$username"
  echo "$password"
}
