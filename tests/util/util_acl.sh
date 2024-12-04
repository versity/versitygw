#!/usr/bin/env bash

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
    if ! display_name=$(echo "$owner" | xmllint --xpath '//*[local-name()="DisplayName"]/text()' - 2>&1); then
      log 2 "error getting display name: $display_name"
      return 1
    fi
    if [ "$display_name" != "$DIRECT_DISPLAY_NAME" ]; then
      log 2 "display name mismatch (expected '$DIRECT_DISPLAY_NAME', actual '$display_name')"
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
