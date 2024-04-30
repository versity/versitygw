#!/usr/bin/env bash

check_for_empty_policy() {
  if [[ $# -ne 2 ]]; then
    echo "check for empty policy command requires command type, bucket name"
    return 1
  fi

  get_bucket_policy "$1" "$2" || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    echo "error getting bucket policy"
    return 1
  fi

  # shellcheck disable=SC2154
  policy=$(echo "$bucket_policy" | jq -r '.Policy')
  statement=$(echo "$policy" | jq -r '.Statement[0]')
  if [[ "" != "$statement" ]] && [[ "null" != "$statement" ]]; then
    echo "policy should be empty (actual value: '$statement')"
    return 1
  fi
  return 0
}