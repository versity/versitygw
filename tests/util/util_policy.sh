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
  if ! check_param_count "check_for_empty_policy" "command type, bucket name" 2 $#; then
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

add_direct_user_to_principal() {
  if [ "${principals[$idx]}" == "*" ]; then
    modified_principal+="\"arn:aws:iam::$DIRECT_AWS_USER_ID:user/$DIRECT_S3_ROOT_ACCOUNT_NAME\""
  else
    modified_principal+="\"arn:aws:iam::$DIRECT_AWS_USER_ID:user/${principals[$idx]}\""
  fi
}

get_modified_principal() {
  log 6 "get_modified_principal"
  if ! check_param_count "get_modified_principal" "principal string" 1 $#; then
    return 1
  fi
  IFS=',' read -r -a principals <<< "$1"
  if [ "$DIRECT" == "true" ]; then
    modified_principal="{\"AWS\": "
  else
    modified_principal=""
  fi
  if [ "${#principals[@]}" -gt 1 ]; then
    modified_principal+="["
  fi
  for ((idx=0; idx<${#principals[@]}; idx++)); do
    if [ "$DIRECT" == "true" ]; then
      add_direct_user_to_principal
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
  if [ "$DIRECT" == "true" ]; then
    modified_principal+="}"
  fi
  log 5 "modified principal: $modified_principal"
}

get_modified_action() {
  log 6 "get_modified_action"
  if ! check_param_count "get_modified_action" "action" 1 $#; then
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
  if ! check_param_count "setup_policy_with_single_statement" "policy file, version, effect, principal, action, resource" 6 $#; then
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
  if ! check_param_count "setup_policy_with_double_statement" "policy file, version, one set of: 'effect, principal, action, resource', another set" 10 $#; then
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
  if ! check_param_count "get_and_check_policy" "client, bucket, expected effect, principal, action, resource" 6 $#; then
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
  if ! check_param_count "check_policy" "policy, expected effect, principal, action, resource" 5 $#; then
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

get_and_check_no_policy_error() {
  if ! check_param_count "get_and_check_no_policy_error" "bucket" 1 $#; then
    return 1
  fi
  if ! get_bucket_policy_rest_expect_code "$1" "404"; then
    log 2 "GetBucketPolicy returned unexpected response code"
    return 1
  fi
  log 5 "response: $bucket_policy"
  if ! bucket_name=$(xmllint --xpath '//*[local-name()="BucketName"]/text()' <(echo -n "$bucket_policy") 2>&1); then
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
  if ! check_param_count "get_and_compare_policy_with_file" "bucket, username, password, filename" 4 $#; then
    return 1
  fi
  # shellcheck disable=SC2002
  if ! sorted_original=$(cat "$4" | jq -S 2>&1); then
    log 2 "error sorting original policy: $sorted_original"
    return 1
  fi
  log 5 "after sort: $sorted_original"
  if ! get_bucket_policy_with_user "$1" "$2" "$3"; then
    log 2 "error getting bucket policy"
    return 1
  fi
  # shellcheck disable=SC2154
  if ! sorted_copy=$(echo -n "$bucket_policy" | jq -S 2>&1); then
    log 2 "error sorting copy: $sorted_copy"
    return 1
  fi
  log 5 "ORIG: $sorted_original"
  log 5 "COPY: $sorted_copy"
  if ! compare_files <(echo -n "$sorted_original") <(echo -n "$sorted_copy"); then
    log 2 "policies not equal"
    return 1
  fi
  return 0
}

put_and_check_policy_rest() {
  if ! check_param_count "put_and_check_policy_rest" "bucket, policy file, effect, principal, action, resource" 6 $#; then
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
  if ! get_bucket_policy_rest "$1"; then
    log 2 "error attempting to get bucket policy response: $result"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    principal="arn:aws:iam::$DIRECT_AWS_USER_ID:user/$4"
  else
    principal="$4"
  fi
  if ! check_policy "$bucket_policy" "$3" "$principal" "$5" "$6"; then
    log 2 "policies not equal"
    return 1
  fi
  return 0
}

log_bucket_policy() {
  log 6 "log_bucket_policy"
  if ! check_param_count "log_bucket_policy" "bucket" 1 $#; then
    return
  fi
  if ! get_bucket_policy "rest" "$1"; then
    log 2 "error getting bucket policy"
    return
  fi
  # shellcheck disable=SC2154
  log 5 "BUCKET POLICY: $bucket_policy"
}
