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
    log 2 "check for empty policy command requires command type, bucket name"
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
    log 2 "policy should be empty (actual value: '$statement')"
    return 1
  fi
  return 0
}

get_modified_principal() {
  log 6 "get_modified_principal"
  if [ $# -ne 1 ]; then
    log 2 "'get_modified_principal' requires principal string"
    return 1
  fi
  IFS=',' read -r -a principals <<< "$1"
  modified_principal=""
  if [ "${#principals[@]}" -gt 1 ]; then
    modified_principal="["
  fi
  for ((idx=0; idx<${#principals[@]}; idx++)); do
    if [ "$DIRECT" == "true" ]; then
      if [ "${principals[$idx]}" == "*" ]; then
        modified_principal+="{\"AWS\": \"arn:aws:iam::$DIRECT_AWS_USER_ID:user/$DIRECT_S3_ROOT_ACCOUNT_NAME\"}"
      else
        modified_principal+="{\"AWS\": \"arn:aws:iam::$DIRECT_AWS_USER_ID:user/${principals[$idx]}\"}"
      fi
    else
      # shellcheck disable=SC2089
      modified_principal+="\"${principals[$idx]}\""
    fi
    if [[ ( "${#principals[@]}" -gt 1 ) && ( $idx -lt ${#principals[@]}-1 ) ]]; then
      modified_principal+=","
    fi
  done
  if [ "${#principals[@]}" -gt 1 ]; then
    modified_principal+="]"
  fi
  log 5 "modified principal: $modified_principal"
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
  printf '{
  "Version": "%s",
  "Statement": [
    {
       "Effect": "%s",
       "Principal": %s,
       "Action": %s,
       "Resource": "%s"
    }
  ]
}' "$2" "$3" "$modified_principal" "$modified_action" "$6" > "$1"
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

get_and_check_policy() {
  if [ $# -ne 6 ]; then
    log 2 "'get_and_check_policy' requires client, bucket, expected effect, principal, action, resource"
    return 1
  fi
  if ! get_bucket_policy "$1" "$BUCKET_ONE_NAME"; then
    log 2 "error getting bucket policy after setting"
    return 1
  fi

  # shellcheck disable=SC2154
  log 5 "POLICY:  $bucket_policy"
  if ! check_policy "$bucket_policy" "$3" "$4" "$5" "$6"; then
    log 2 "error checking policy"
    return 1
  fi
  return 0
}

check_policy() {
  if [ $# -ne 5 ]; then
    log 2 "'check_policy' requires policy, expected effect, policy, action, resource"
    return 1
  fi
  log 5 "policy: $1"
  if ! statement=$(echo -n "$1" | jq -r '.Statement[0]' 2>&1); then
    log 2 "error getting statement value: $statement"
    return 1
  fi
  if ! returned_effect=$(echo "$statement" | jq -r '.Effect' 2>&1); then
    log 2 "error getting effect: $returned_effect"
    return 1
  fi
  if [[ "$2" != "$returned_effect" ]]; then
    log 2 "effect mismatch (expected '$2', actual '$returned_effect')"
    return 1
  fi
  if ! returned_principal=$(echo "$statement" | jq -r '.Principal' 2>&1); then
    log 2 "error getting principal: $returned_principal"
    return 1
  fi
  if [[ -n $DIRECT ]] && arn=$(echo "$returned_principal" | jq -r '.AWS' 2>&1); then
    if [[ $arn != "$3" ]]; then
      log 2 "arn mismatch (expected '$3', actual '$arn')"
      return 1
    fi
  else
    if [[ "$3" != "$returned_principal" ]]; then
      log 2 "principal mismatch (expected '$3', actual '$returned_principal')"
      return 1
    fi
  fi
  if ! returned_action=$(echo "$statement" | jq -r '.Action' 2>&1); then
    log 2 "error getting action: $returned_action"
    return 1
  fi
  if [[ "$4" != "$returned_action" ]]; then
    log 2 "action mismatch (expected '$4', actual '$returned_action')"
    return 1
  fi
  if ! returned_resource=$(echo "$statement" | jq -r '.Resource' 2>&1); then
    log 2 "error getting resource: $returned_resource"
    return 1
  fi
  if [[ "$5" != "$returned_resource" ]]; then
    log 2 "resource mismatch (expected '$5', actual '$returned_resource')"
    return 1
  fi
    return 0
}

put_and_check_for_malformed_policy() {
  if [ $# -ne 2 ]; then
    log 2 "'put_and_check_for_malformed_policy' requires bucket name, policy file"
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

get_and_check_no_policy_error() {
  if [ $# -ne 1 ]; then
    log 2 "'get_and_check_no_policy_error' requires bucket name"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/get_bucket_policy.sh); then
    log 2 "error attempting to get bucket policy response: $result"
    return 1
  fi
  if [ "$result" != "404" ]; then
    log 2 "GetBucketOwnershipControls returned unexpected response code: $result, reply:  $(cat "$TEST_FILE_FOLDER/response.txt")"
    return 1
  fi
  log 5 "response: $(cat "$TEST_FILE_FOLDER/response.txt")"
  if ! bucket_name=$(xmllint --xpath '//*[local-name()="BucketName"]/text()' "$TEST_FILE_FOLDER/response.txt" 2>&1); then
    log 2 "error getting bucket name: $bucket_name"
    return 1
  fi
  if [ "$bucket_name" != "$1" ]; then
    log 2 "rule mismatch (expected '$1', actual '$bucket_name')"
    return 1
  fi
  return 0
}

get_and_compare_policy_with_file() {
  if [ $# -ne 4 ]; then
    log 2 "'get_and_compare_policies' requires bucket, username, password, filename"
    return 1
  fi
  if ! get_bucket_policy_with_user "$1" "$2" "$3"; then
    log 2 "error getting bucket policy"
    return 1
  fi
  # shellcheck disable=SC2154
  echo -n "$bucket_policy" > "$4-copy"
  log 5 "ORIG: $(cat "$4")"
  log 5 "COPY: $(cat "$4-copy")"
  if ! compare_files "$4" "$4-copy"; then
    log 2 "policies not equal"
    return 1
  fi
  return 0
}

put_and_check_policy_rest() {
  if [ $# -ne 6 ]; then
    log 2 "'put_policy_rest' requires bucket name, policy file, effect, principal, action, resource"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" POLICY_FILE="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_bucket_policy.sh); then
    log 2 "error putting policy: $result"
    return 1
  fi
  log 5 "response code: $result"
  if [[ ( "$result" != "204" ) && ( "$result" != "200" ) ]]; then
    log 2 "unexpected response code, expected '200' or '204', actual '$result' (reply: $(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/policy.txt" ./tests/rest_scripts/get_bucket_policy.sh); then
    log 2 "error attempting to get bucket policy response: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "unexpected response code, expected '200', actual '$result' (reply: $(cat "$TEST_FILE_FOLDER/policy.txt"))"
    return 1
  fi
  log 5 "policy: $(cat "$TEST_FILE_FOLDER/policy.txt")"
  if [ "$DIRECT" == "true" ]; then
    principal="arn:aws:iam::$DIRECT_AWS_USER_ID:user/$4"
  else
    principal="$4"
  fi
  if ! check_policy "$(cat "$TEST_FILE_FOLDER/policy.txt")" "$3" "$principal" "$5" "$6"; then
    log 2 "policies not equal"
    return 1
  fi
  return 0
}

log_bucket_policy() {
  if [ $# -ne 1 ]; then
    log 2 "'log_bucket_policy' requires bucket name"
    return
  fi
  if ! get_bucket_policy "s3api" "$1"; then
    log 2 "error getting bucket policy"
    return
  fi
  # shellcheck disable=SC2154
  log 5 "BUCKET POLICY: $bucket_policy"
}
