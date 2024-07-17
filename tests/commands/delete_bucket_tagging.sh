#!/usr/bin/env bash

delete_bucket_tagging() {
  record_command "delete-bucket-tagging" "client:$1"
  if [ $# -ne 2 ]; then
    log 2 "delete bucket tagging command missing command type, bucket name"
    return 1
  fi
  local result
  if [[ $1 == 'aws' ]]; then
    tags=$(aws --no-verify-ssl s3api delete-bucket-tagging --bucket "$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(mc --insecure tag remove "$MC_ALIAS"/"$2" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    log 2 "error deleting bucket tagging: $tags"
    return 1
  fi
  return 0
}
