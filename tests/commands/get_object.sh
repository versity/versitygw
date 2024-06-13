#!/usr/bin/env bash

get_object() {
  if [ $# -ne 4 ]; then
    log 2 "get object command requires command type, bucket, key, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 mv "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate get "s3://$2/$3" "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure get "$MC_ALIAS/$2/$3" "$4" 2>&1) || exit_code=$?
  else
    log 2 "'get object' command not implemented for '$1'"
    return 1
  fi
  log 5 "get object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $error"
    return 1
  fi
  return 0
}

get_object_with_range() {
  if [[ $# -ne 4 ]]; then
    log 2 "'get object with range' requires bucket, key, range, outfile"
    return 1
  fi
  error=$(aws --no-verify-ssl s3api get-object --bucket "$1" --key "$2" --range "$3" "$4" 2>&1) || local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    log 2 "error getting object with range: $error"
    return 1
  fi
  return 0
}

get_object_with_user() {
  if [ $# -ne 6 ]; then
    log 2 "'get object with user' command requires command type, bucket, key, save location, aws ID, aws secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    get_object_error=$(AWS_ACCESS_KEY_ID="$5" AWS_SECRET_ACCESS_KEY="$6" aws --no-verify-ssl s3api get-object --bucket "$2" --key "$3" "$4" 2>&1) || exit_code=$?
  else
    log 2 "'get object with user' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error getting object: $get_object_error"
    export get_object_error
    return 1
  fi
  return 0
}
