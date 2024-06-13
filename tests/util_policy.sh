#!/usr/bin/env bash

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

setup_policy_with_single_statement() {
  if [[ $# -ne 6 ]]; then
    "'setup single policy' command requires file, version, effect, principal, action, resource"
  fi
  cat <<EOF > "$1"
{
  "Version": "$2",
  "Statement": [
    {
       "Effect": "$3",
       "Principal": "$4",
       "Action": "$5",
       "Resource": "$6"
    }
  ]
}
EOF
log 5 "$(cat "$1")"
}
