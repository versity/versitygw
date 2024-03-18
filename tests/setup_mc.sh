#!/usr/bin/env bash

check_for_alias() {
  local alias_result
  aliases=$(mc alias list)
  if [[ $alias_result -ne 0 ]]; then
    echo "error checking for aliases: $aliases"
    return 2
  fi
  while IFS= read -r line; do
    error=$(echo "$line" | grep -w "$MC_ALIAS ")
    if [[ $? -eq 0 ]]; then
      return 0
    fi
  done <<< "$aliases"
  return 1
}

check_add_mc_alias() {
  check_for_alias || alias_result=$?
  if [[ $alias_result -eq 2 ]]; then
    echo "error checking for aliases"
    return 1
  fi
  if [[ $alias_result -eq 0 ]]; then
    return 0
  fi
  local set_result
  error=$(mc alias set --insecure "$MC_ALIAS" "$AWS_ENDPOINT_URL" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY") || set_result=$?
  if [[ $set_result -ne 0 ]]; then
    echo "error setting alias: $error"
    return 1
  fi
  return 0
}