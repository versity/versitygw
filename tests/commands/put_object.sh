#!/usr/bin/env bash

source ./tests/report.sh

put_object() {
  log 6 "put_object"
  record_command "put-object" "client:$1"
  if [ $# -ne 4 ]; then
    log 2 "put object command requires command type, source, destination bucket, destination key"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 mv "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure put "$2" "$MC_ALIAS/$3/$4" 2>&1) || exit_code=$?
  else
    log 2 "'put object' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error putting object into bucket: $error"
    return 1
  fi
  return 0
}

put_object_with_user() {
  record_command "put-object" "client:$1"
  if [ $# -ne 6 ]; then
    log 2 "put object command requires command type, source, destination bucket, destination key, aws ID, aws secret key"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    put_object_error=$(AWS_ACCESS_KEY_ID="$5" AWS_SECRET_ACCESS_KEY="$6" aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  else
    log 2 "'put object with user' command not implemented for '$1'"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error putting object into bucket: $put_object_error"
    export put_object_error
    return 1
  fi
  return 0
}
