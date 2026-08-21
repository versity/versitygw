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

source ./tests/env.sh
source ./tests/report.sh
source ./tests/setup_common.sh
source ./tests/setup_mc.sh
source ./tests/drivers/delete_bucket/delete_bucket_rest.sh
source ./tests/util/util_object.sh
source ./tests/versity.sh

check_secrets_line() {
  if [[ $secrets_line =~ ^(USER_ID_(ADMIN|USERPLUS|USER)_[0-9])= ]]; then
    match=${BASH_REMATCH[1]}
    role=$(echo -n "${BASH_REMATCH[2]}" | tr '[:upper:]' '[:lower:]')

    if [ -z "${!match}" ]; then
      log 2 "$match secrets parameter missing"
      return 1
    fi
    username_env="${match/USER_ID/USERNAME}"
    password_env="${match/USER_ID/PASSWORD}"
    if [ -z "${!username_env}" ]; then
      log 2 "$username_env secrets parameter missing"
      return 1
    fi
    if [ -z "${!password_env}" ]; then
      log 2 "$password_env secrets parameter missing"
      return 1
    fi
    local user_exists_code=0
    user_exists "${!username_env}" || user_exists_code=$?
    if [ $user_exists_code -eq 2 ]; then
      log 2 "error checking for user existence"
      return 1
    fi
    if [ $user_exists_code -eq 1 ] && ! create_user_versitygw "${!username_env}" "${!password_env}" "$role"; then
      log 2 "error creating user"
      return 1
    fi
  fi
  return 0
}

static_user_versitygw_setup() {
  while read -r secrets_line || [ -n "$secrets_line" ]; do
    if ! check_secrets_line; then
      return 1
    fi
  done < "$SECRETS_FILE"
}

# bats setup function
setup() {
  local response

  if ! setup_env; then
    log 1 "error setting up env"
    return 1
  fi

  if ! setup_versitygw; then
    log 1 "error starting versitygw app: $response"
    return 1
  fi

  if ! setup_clients; then
    log 1 "error setting up clients"
    return 1
  fi
}

# bats teardown function
teardown() {
  teardown_common
}
