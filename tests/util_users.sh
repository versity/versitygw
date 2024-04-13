#!/usr/bin/env bash

create_user() {
  if [[ $# -ne 3 ]]; then
    echo "create user command requires user ID, key, and role"
    return 1
  fi
  create_user_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2" "$3" || create_result=$?
  if [[ $create_result -ne 0 ]]; then
    echo "error creating user: $error"
    return 1
  fi
  return 0
}

create_user_with_user() {
  if [[ $# -ne 5 ]]; then
    echo "create user with user command requires creator ID, key, and new user ID, key, and role"
    return 1
  fi
  error=$($VERSITY_EXE admin --allow-insecure --access "$1" --secret "$2" --endpoint-url "$AWS_ENDPOINT_URL" create-user --access "$3" --secret "$4" --role "$5") || local create_result=$?
  if [[ $create_result -ne 0 ]]; then
    echo "error creating user: $error"
    return 1
  fi
  return 0
}

list_users() {
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
    echo "user exists command requires username"
    return 2
  fi
  list_users || local list_result=$?
  if [[ $list_result -ne 0 ]]; then
    echo "error listing user"
    return 2
  fi
  for element in "${parsed_users[@]}"; do
    if [[ $element == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

delete_user() {
  if [[ $# -ne 1 ]]; then
      echo "delete user command requires user ID"
      return 1
    fi
    error=$($VERSITY_EXE admin --allow-insecure --access $AWS_ACCESS_KEY_ID --secret $AWS_SECRET_ACCESS_KEY --endpoint-url $AWS_ENDPOINT_URL delete-user --access "$1") || local delete_result=$?
    if [[ $delete_result -ne 0 ]]; then
      echo "error deleting user: $error"
      return 1
    fi
    return 0
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
