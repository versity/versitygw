#!/usr/bin/env bash

# delete an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket() {
  if [ $# -ne 2 ]; then
    log 2 "delete bucket missing command type, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 rb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api delete-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure rb "$MC_ALIAS/$2" 2>&1) || exit_code=$?
  else
    log 2 "Invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    else
      log 2 "error deleting bucket: $error"
      return 1
    fi
  fi
  return 0
}