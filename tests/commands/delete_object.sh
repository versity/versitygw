#!/usr/bin/env bash

delete_object() {
  if [ $# -ne 3 ]; then
    log 2 "delete object command requires command type, bucket, key"
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
    log 2 "invalid command type $1"
    return 1
  fi
  log 5 "delete object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error deleting object: $error"
    return 1
  fi
  return 0
}

delete_object_with_user() {
  if [ $# -ne 5 ]; then
    log 2 "delete object with user command requires command type, bucket, key, access ID, secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3' ]]; then
    error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" aws --no-verify-ssl s3 rm "s3://$2/$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" aws --no-verify-ssl s3api delete-object --bucket "$2" --key "$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rm --access_key="$4" --secret_key="$5" "s3://$2/$3" 2>&1) || exit_code=$?
  else
    log 2 "command 'delete object with user' not implemented for '$1'"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error deleting object: $error"
    export error
    return 1
  fi
  return 0
}