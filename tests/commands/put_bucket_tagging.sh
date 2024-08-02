#!/usr/bin/env bash

put_bucket_tagging() {
  if [ $# -ne 4 ]; then
    echo "bucket tag command missing command type, bucket name, key, value"
    return 1
  fi
  local error
  local result
  record_command "put-bucket-tagging" "client:$1"
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-bucket-tagging --bucket "$2" --tagging "TagSet=[{Key=$3,Value=$4}]") || result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure tag set "$MC_ALIAS"/"$2" "$3=$4" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    echo "Error adding bucket tag: $error"
    return 1
  fi
  return 0
}

put_bucket_tagging_with_user() {
  log 5 "checking for bucket name, key, value, username, password"
  assert [ $# -eq 5 ]
  record_command "put-bucket-tagging" "client:$1"
  if ! error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" aws --no-verify-ssl s3api put-bucket-tagging --bucket "$1" --tagging "TagSet=[{Key=$2,Value=$3}]"); then
    log 2 "error putting bucket tagging: $error"
    return 1
  fi
  return 0
}
