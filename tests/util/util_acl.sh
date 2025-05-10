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

get_check_default_acl_s3cmd() {
  if [ $# -ne 1 ]; then
    log 2 "'get_check_acl_s3cmd' requires bucket name"
    return 1
  fi
  if ! get_bucket_acl "s3cmd" "$BUCKET_ONE_NAME"; then
    log 2 "error retrieving acl"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "Initial ACLs: $acl"
  acl_line=$(echo "$acl" | grep "ACL")
  user_id=$(echo "$acl_line" | awk '{print $2}')
  if [[ $DIRECT == "true" ]]; then
    if [[ $user_id != "$DIRECT_DISPLAY_NAME:" ]]; then
      log 2 "ID mismatch ($user_id, $DIRECT_DISPLAY_NAME)"
      return 1
    fi
  else
    if [[ $user_id != "$AWS_ACCESS_KEY_ID:" ]]; then
      log 2 "ID mismatch ($user_id, $AWS_ACCESS_KEY_ID)"
      return 1
    fi
  fi
  permission=$(echo "$acl_line" | awk '{print $3}')
  if [[ $permission != "FULL_CONTROL" ]]; then
    log 2 "Permission mismatch ($permission)"
    return 1
  fi
  return 0
}

get_check_post_change_acl_s3cmd() {
  if [ $# -ne 1 ]; then
    log 2 "'get_check_post_change_acl_s3cmd' requires bucket name"
    return 1
  fi
  if ! get_bucket_acl "s3cmd" "$1"; then
    log 2 "error retrieving acl"
    return 1
  fi
  log 5 "ACL after read put: $acl"
  acl_lines=$(echo "$acl" | grep "ACL")
  log 5 "ACL lines:  $acl_lines"
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "$acl_lines"
  log 5 "lines: ${lines[*]}"
  if [[ ${#lines[@]} -ne 2 ]]; then
    log 2 "unexpected number of ACL lines: ${#lines[@]}"
    return 1
  fi
  anon_name=$(echo "${lines[1]}" | awk '{print $2}')
  anon_permission=$(echo "${lines[1]}" | awk '{print $3}')
  if [[ $anon_name != "*anon*:" ]]; then
    log 2 "unexpected anon name: $anon_name"
    return 1
  fi
  if [[ $anon_permission != "READ" ]]; then
    log 2 "unexpected anon permission: $anon_permission"
    return 1
  fi
  return 0
}

get_check_acl_id() {
  if [ $# -ne 2 ]; then
    log 2 "'get_check_acl_id' requires client, bucket"
    return 1
  fi
  if ! get_bucket_acl "$1" "$2"; then
    log 2 "error retrieving acl"
    return 1
  fi
  log 5 "Initial ACLs: $acl"
  if ! id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Owner.ID' 2>&1); then
    log 2 "error getting ID: $id"
    return 1
  fi
  if [[ $id != "$AWS_ACCESS_KEY_ID" ]]; then
    # for direct, ID is canonical user ID rather than AWS_ACCESS_KEY_ID
    if ! canonical_id=$(aws --no-verify-ssl s3api list-buckets --query 'Owner.ID' 2>&1); then
      log 2 "error getting canonical ID: $canonical_id"
      return 1
    fi
    canonical_id="$(echo -n "$canonical_id" | grep -v "InsecureRequestWarning" | sed "s/\"//g")"
    log 5 "canonical ID: $canonical_id"
    if [[ $id != "$canonical_id" ]]; then
      log 2 "acl ID doesn't match AWS key or canonical ID"
      return 1
    fi
  fi
  return 0
}

get_check_acl_after_first_put() {
  if [ $# -ne 2 ]; then
    log 2 "'get_check_acl_after_first_put' requires client, bucket"
    return 1
  fi
  if ! get_bucket_acl "$1" "$BUCKET_ONE_NAME"; then
    log 2 "error retrieving second ACL"
    return 1
  fi
  log 5 "Acls after 1st put: $acl"
  if ! public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants[1]' 2>&1); then
    log 2 "error getting public grants: $public_grants"
    return 1
  fi
  if ! permission=$(echo "$public_grants" | jq -r '.Permission' 2>&1); then
    log 2 "error getting permission: $permission"
    return 1
  fi
  if [[ $permission != "READ" ]]; then
    log 2 "incorrect permission ($permission)"
    return 1
  fi
  return 0
}

get_check_acl_after_second_put() {
  if [ $# -ne 2 ]; then
    log 2 "'get_check_acl_after_second_put' requires client, bucket"
    return 1
  fi
  if ! get_bucket_acl "$1" "$BUCKET_ONE_NAME"; then
    log 2 "error retrieving third ACL"
    return 1
  fi
  if ! public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants' 2>&1); then
    log 2 "error retrieving public grants: $public_grants"
    return 1
  fi
  if ! public_grant_length=$(echo "$public_grants" | jq -r 'length' 2>&1); then
    log 2 "Error retrieving public grant length: $public_grant_length"
    return 1
  fi
  if [[ $public_grant_length -ne 2 ]]; then
    log 2 "incorrect grant length for private ACL ($public_grant_length)"
    return 1
  fi
  if ! permission=$(echo "$public_grants" | jq -r '.[0].Permission' 2>&1); then
    log 2 "Error retrieving permission: $permission"
    return 1
  fi
  if [[ $permission != "FULL_CONTROL" ]]; then
    log 2 "incorrect permission ($permission)"
    return 1
  fi
  return 0
}

get_check_acl_after_policy() {
  if [ $# -ne 1 ]; then
    log 2 "'get_check_acl_after_policy' requires bucket name"
    return 1
  fi
  if ! get_bucket_acl "s3api" "$1"; then
    log 2 "error getting bucket acl"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "ACL: $acl"
  if ! second_grant=$(echo "$acl" | jq -r ".Grants[1]" 2>&1); then
    log 2 "error getting second grant: $second_grant"
    return 1
  fi
  if ! second_grantee=$(echo "$second_grant" | jq -r ".Grantee" 2>&1); then
    log 2 "error getting second grantee: $second_grantee"
    return 1
  fi
  if ! permission=$(echo "$second_grant" | jq -r ".Permission" 2>&1); then
    log 2 "error getting permission: $permission"
    return 1
  fi
  log 5 "second grantee: $second_grantee"
  if [[ $permission != "READ" ]]; then
    log 2 "incorrect permission: $permission"
    return 1
  fi
  if [[ $DIRECT == "true" ]]; then
    if ! uri=$(echo "$second_grantee" | jq -r ".URI" 2>&1); then
      log 2 "error getting uri: $uri"
      return 1
    fi
    if [[ $uri != "http://acs.amazonaws.com/groups/global/AllUsers" ]]; then
      log 2 "unexpected URI: $uri"
      return 1
    fi
  else
    if ! id=$(echo "$second_grantee" | jq -r ".ID" 2>&1); then
      log 2 "error getting ID: $id"
      return 1
    fi
    if [[ $id != "all-users" ]]; then
      log 2 "unexpected ID: $id"
      return 1
    fi
  fi
}

check_direct_display_name() {
  if ! display_name=$(echo "$owner" | xmllint --xpath '//*[local-name()="DisplayName"]/text()' - 2>&1); then
    log 2 "error getting display name: $display_name"
    return 1
  fi
  if [ "$display_name" != "$DIRECT_DISPLAY_NAME" ]; then
    log 2 "display name mismatch (expected '$DIRECT_DISPLAY_NAME', actual '$display_name')"
    return 1
  fi
}

get_and_check_acl_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'get_and_check_acl_rest' requires bucket name"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/acl.txt" ./tests/rest_scripts/get_bucket_acl.sh); then
    log 2 "error attempting to get bucket ACL response: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "get acl returned code '$result' (message: $(cat "$TEST_FILE_FOLDER/acl.txt"))"
    return 1
  fi
  log 5 "acl: $(cat "$TEST_FILE_FOLDER/acl.txt")"
  if ! access_control_policy=$(xmllint --xpath '//*[local-name()="AccessControlPolicy"]' "$TEST_FILE_FOLDER/acl.txt" 2>&1); then
    log 2 "error getting access control policy: $access_control_policy"
    return 1
  fi
  if ! owner=$(echo "$access_control_policy" | xmllint --xpath '//*[local-name()="Owner"]' - 2>&1); then
    log 2 "error getting owner information: $owner"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    if ! check_direct_display_name; then
      log 2 "error checking direct display name"
      return 1
    fi
  else
    if ! id=$(echo "$owner" | xmllint --xpath '//*[local-name()="ID"]/text()' - 2>&1); then
      log 2 "error getting ID: $id"
      return 1
    fi
    if [ "$id" != "$AWS_ACCESS_KEY_ID" ]; then
      log 2 "ID mismatch"
      return 1
    fi
  fi
  return 0
}

setup_acl() {
  if ! check_param_count "setup_acl" "acl file, grantee type, grantee, permission, owner ID" 5 $#; then
    return 1
  fi
  cat <<EOF > "$1"
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
      <ID>$5</ID>
  </Owner>
  <AccessControlList>
      <Grant>
          <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="$2">
              <ID>$3</ID>
          </Grantee>
          <Permission>$4</Permission>
      </Grant>
  </AccessControlList>
</AccessControlPolicy>
EOF
}

setup_acl_json() {
  if [ $# -ne 5 ]; then
    log 2 "'setup_acl_json' requires acl file, grantee type, grantee ID, permission, owner ID"
    return 1
  fi
  cat <<EOF > "$1"
{
  "Grants": [
    {
      "Grantee": {
        "Type": "$2",
        "ID": "$3"
      },
      "Permission": "$4"
    }
  ],
  "Owner": {
    "ID": "$5"
  }
}
EOF
}

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
    echo "$AWS_CANONICAL_ID"
    echo "$ACL_AWS_CANONICAL_ID"
    echo "$ACL_AWS_ACCESS_KEY_ID"
    echo "$ACL_AWS_SECRET_ACCESS_KEY"
  else
    echo "$AWS_ACCESS_KEY_ID"
    if ! create_user_versitygw "$1" "$2" "user"; then
      log 2 "error creating versitygw user"
      return 1
    fi
    # shellcheck disable=SC2154
    echo "$1"
    echo "$1"
    # shellcheck disable=SC2154
    echo "$2"
  fi
}

put_invalid_acl_rest_verify_failure() {
  if [ $# -ne 2 ]; then
    log 2 "'put_invalid_acl_rest_verify_failure' requires bucket name, ACL file"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" ACL_FILE="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/put_bucket_acl.sh); then
    log 2 "error attempting to put bucket acl: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "response returned code: $result (error: $(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  if ! error_code=$(xmllint --xpath '//*[local-name()="Code"]/text()' "$TEST_FILE_FOLDER/response.txt" 2>&1); then
    log 2 "error getting display name: $error_code"
    return 1
  fi
  if [ "$error_code" != "MalformedACLError" ]; then
    log 2 "invalid error code, expected 'MalformedACLError', was '$error_code'"
    return 1
  fi
  return 0
}

# param: bucket name
# return 0 for success, 1 for failure
check_ownership_rule_and_reset_acl() {
  if [ $# -ne 1 ]; then
    log 2 "'check_ownership_rule_and_reset_acl' requires bucket name"
    return 1
  fi
  if ! object_ownership_rule=$(get_bucket_ownership_controls_rest "$1" 2>&1); then
    log 2 "error getting bucket ownership controls"
    return 1
  fi
  log 5 "ownership rule: $object_ownership_rule"
  if [[ $object_ownership_rule != "BucketOwnerEnforced" ]] && ! reset_bucket_acl "$1"; then
    log 2 "error resetting bucket ACL"
    return 1
  fi
}

# get object acl
# param:  object path
# export acl for success, return 1 for error
get_object_acl() {
  if [ $# -ne 2 ]; then
    log 2 "object ACL command missing object name"
    return 1
  fi
  local exit_code=0
  acl=$(aws --no-verify-ssl s3api get-object-acl --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    log 2 "Error getting object ACLs: $acl"
    return 1
  fi
  export acl
}
