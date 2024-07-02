#!/usr/bin/env bash

setup_user() {
  if [[ $# -ne 2 ]]; then
    log 2 "'setup user' command requires user ID or username, and role"
    return 1
  fi
  if user_exists "$1"; then
    if ! delete_user "$1"; then
      log 2 "error deleting user '$1'"
      return 1
    fi
  fi
  if ! create_user "$1" "$2"; then
    log 2 "error creating user '$1'"
    return 1
  fi
  return 0
}

create_user() {
  if [[ $# -ne 2 ]]; then
    log 2 "create user command requires user ID or username, and role"
    return 1
  fi
  if [[ $DIRECT == "true" ]]; then
    if ! create_user_direct "$1" "$2"; then
      log 2 "error creating user direct via s3"
      return 1
    fi
    return 0
  fi
  if [[ -n "$versitygw_user_key" ]]; then
    log 2 "for setup user via versitygw, 'versitygw_user_key' must be defined"
    return 1
  fi
  if ! create_user_versitygw "$1" "$versitygw_user_key" "$3"; then
    log 2 "error creating user via versitygw"
    return 1
  fi
  return 0
}

create_user_versitygw() {
  if [[ $# -ne 3 ]]; then
    log 2 "create user command requires user ID, key, and role"
    return 1
  fi
  if ! create_user_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2" "$3"; then
    log 2 "error creating user"
    return 1
  fi
  return 0
}

create_user_if_nonexistent() {
  if [[ $# -ne 3 ]]; then
    echo "create user command requires user ID, key, and role"
    return 1
  fi
  if user_exists "$1"; then
    log 5 "user $1 already exists"
    return 0
  fi
  create_user "$1" "$2" "$3"
  return $?
}

create_user_direct() {
  # TODO change policies based on role
  if [[ $# -ne 2 ]]; then
    log 2 "create user direct command requires desired username, role"
    return 1
  fi
  if ! error=$(AWS_ENDPOINT_URL="" aws iam create-user --user-name "$1" 2>&1); then
    log 2 "error creating new user: $error"
    return 1
  fi
  return 0
}

create_user_with_user() {
  if [[ $# -ne 5 ]]; then
    log 2 "create user with user command requires creator ID, key, and new user ID, key, and role"
    return 1
  fi
  if ! error=$($VERSITY_EXE admin --allow-insecure --access "$1" --secret "$2" --endpoint-url "$AWS_ENDPOINT_URL" create-user --access "$3" --secret "$4" --role "$5" 2>&1); then
    log 2 "error creating user: $error"
    return 1
  fi
  return 0
}

list_users_direct() {
  # AWS_ENDPOINT_URL of s3.amazonaws.com doesn't work here
  if ! users=$(AWS_ENDPOINT_URL="" aws --profile="$AWS_PROFILE" iam list-users 2>&1); then
    log 2 "error listing users via direct s3 call: $users"
    return 1
  fi
  parsed_users=()
  if ! users_list=$(echo "$users" | jq -r ".Users[].UserName" 2>&1); then
    log 2 "error parsing users array: $users_list"
    return 1
  fi
  while IFS= read -r line; do
    parsed_users+=("$line")
  done <<< "$users_list"
  log 5 "parsed users: ${parsed_users[*]}"
  export parsed_users
  return 0
}

list_users() {
  if [[ $DIRECT == "true" ]]; then
    if ! list_users_direct; then
      log 2 "error listing users via direct s3 call"
      return 1
    fi
    return 0
  fi
  if ! list_users_versitygw; then
    log 2 "error listing versitygw users"
    return 1
  fi
  return 0
}

list_users_versitygw() {
  users=$($VERSITY_EXE admin --allow-insecure --access "$AWS_ACCESS_KEY_ID" --secret "$AWS_SECRET_ACCESS_KEY" --endpoint-url "$AWS_ENDPOINT_URL" list-users) || local list_result=$?
  if [[ $list_result -ne 0 ]]; then
    echo "error listing users: $users"
    return 1
  fi
  parsed_users=()
  while IFS= read -r line; do
    parsed_users+=("$line")
  done < <(awk 'NR>2 {print $1}' <<< "$users")
  export parsed_users
  return 0
}

user_exists() {
  if [[ $# -ne 1 ]]; then
    log 2 "user exists command requires username"
    return 2
  fi
  if ! list_users; then
    log 2 "error listing user"
    return 2
  fi
  for element in "${parsed_users[@]}"; do
    log 5 "user: $element"
    if [[ $element == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

delete_user_direct() {
  if [[ $# -ne 1 ]]; then
    log 2 "delete user direct command requires username"
    return 1
  fi
  if ! error=$(AWS_ENDPOINT_URL="" aws --profile="$AWS_PROFILE" iam delete-user --user-name "$1" 2>&1); then
    log 2 "error deleting user: $error"
    return 1
  fi
  return 0
}

delete_user_versitygw() {
  if [[ $# -ne 1 ]]; then
    log 2 "delete user via versitygw command requires user ID or username"
    return 1
  fi
  log 5 "$VERSITY_EXE admin --allow-insecure --access $AWS_ACCESS_KEY_ID --secret $AWS_SECRET_ACCESS_KEY --endpoint-url $AWS_ENDPOINT_URL delete-user --access $1"
  if ! error=$($VERSITY_EXE admin --allow-insecure --access "$AWS_ACCESS_KEY_ID" --secret "$AWS_SECRET_ACCESS_KEY" --endpoint-url "$AWS_ENDPOINT_URL" delete-user --access "$1" 2>&1); then
    log 2 "error deleting user: $error"
    export error
    return 1
  fi
  return 0
}

delete_user() {
  if [[ $# -ne 1 ]]; then
    log 2 "delete user command requires user ID"
    return 1
  fi
  if [[ $DIRECT == "true" ]]; then
    if ! delete_user_direct "$1"; then
      log 2 "error deleting user direct via s3"
      return 1
    fi
    log 5 "user '$1' deleted successfully"
    return 0
  fi
  if ! delete_user_versitygw "$1"; then
    log 2 "error deleting user via versitygw"
    return 1
  fi
}

change_bucket_owner() {
  if [[ $# -ne 4 ]]; then
      echo "change bucket owner command requires ID, key, bucket name, and new owner"
      return 1
    fi
    error=$($VERSITY_EXE admin --allow-insecure --access "$1" --secret "$2" --endpoint-url "$AWS_ENDPOINT_URL" change-bucket-owner --bucket "$3" --owner "$4" 2>&1) || local change_result=$?
    if [[ $change_result -ne 0 ]]; then
      echo "error changing bucket owner: $error"
      return 1
    fi
    return 0
}
