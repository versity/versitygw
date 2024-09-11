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

check_for_empty_policy() {
  if [[ $# -ne 2 ]]; then
    echo "check for empty policy command requires command type, bucket name"
    return 1
  fi

  if ! get_bucket_policy "$1" "$2"; then
    log 2 "error getting bucket policy"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "bucket policy: $bucket_policy"

  # shellcheck disable=SC2154
  if [[ $bucket_policy == "" ]]; then
    return 0
  fi

  #policy=$(echo "$bucket_policy" | jq -r '.Policy')
  statement=$(echo "$bucket_policy" | jq -r '.Statement[0]')
  log 5 "statement: $statement"
  if [[ "" != "$statement" ]] && [[ "null" != "$statement" ]]; then
    echo "policy should be empty (actual value: '$statement')"
    return 1
  fi
  return 0
}

get_modified_principal() {
  log 6 "get_modified_principal"
  if [ $# -ne 1 ]; then
    log 2 "'get_modified_principal' requires principal"
    return 1
  fi
  local first_char="${1:0:1}"
  if [ "$first_char" != '{' ] && [ "$first_char" != '[' ] && [ "$first_char" != '"' ]; then
    # shellcheck disable=SC2089
    modified_principal="\"$1\""
  else
    modified_principal=$1
  fi
}

get_modified_action() {
  log 6 "get_modified_action"
  if [ $# -ne 1 ]; then
    log 2 "'get_modified_action' requires action"
    return 1
  fi
  local first_char="${1:0:1}"
  if [ "$first_char" != '{' ] && [ "$first_char" != '[' ] && [ "$first_char" != '"' ]; then
    # shellcheck disable=SC2089
    modified_action="\"$1\""
  else
    modified_action=$1
  fi
}

# params:  file, version, effect, principal, action, resource
# fail on error
setup_policy_with_single_statement() {
  log 6 "setup_policy_with_single_statement"
  if [ $# -ne 6 ]; then
    log 2 "'setup_policy_with_single_statement' requires policy file, version, effect, principal, action, resource"
    return 1
  fi
  log 5 "policy file: $1"
  if ! get_modified_principal "$4"; then
    log 2 "error getting modified principal"
    return 1
  fi
  if ! get_modified_action "$5"; then
    log 2 "error getting modified action"
    return 1
  fi
  bash -c "cat <<EOF > $1
{
  \"Version\": \"$2\",
  \"Statement\": [
    {
       \"Effect\": \"$3\",
       \"Principal\": $modified_principal,
       \"Action\": $modified_action,
       \"Resource\": \"$6\"
    }
  ]
}
EOF"
  # shellcheck disable=SC2154
  #assert_success "failed to set up policy: $output"
  log 5 "policy data: $(cat "$1")"
}

# params:  file, version, two sets:  effect, principal, action, resource
# return 0 on success, 1 on error
setup_policy_with_double_statement() {
  log 6 "setup_policy_with_double_statement"
  if [ $# -ne 10 ]; then
    log 2 "invalid number of parameters"
    return 1
  fi
  if ! get_modified_principal "$4"; then
    log 2 "error getting first modified principal"
    return 1
  fi
  principal_one=$modified_principal
  if ! get_modified_principal "$8"; then
    log 2 "error getting second modified principal"
    return 1
  fi
  principal_two=$modified_principal
  bash -c "cat <<EOF > $1
{
  \"Version\": \"$2\",
  \"Statement\": [
    {
       \"Effect\": \"$3\",
       \"Principal\": $principal_one,
       \"Action\": \"$5\",
       \"Resource\": \"$6\"
    },
    {
       \"Effect\": \"$7\",
       \"Principal\": $principal_two,
       \"Action\": \"$9\",
       \"Resource\": \"${10}\"
    }
  ]
}
EOF"
  # shellcheck disable=SC2154
  log 5 "policy data: $(cat "$1")"
}