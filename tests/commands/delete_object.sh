#!/usr/bin/env bash

delete_object() {
  if [ $# -ne 3 ]; then
    echo "delete object command requires command type, bucket, key"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api delete-object --bucket "$2" --key "$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure rm "$MC_ALIAS/$2/$3" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error deleting object: $error"
    return 1
  fi
  return 0
}