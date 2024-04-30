#!/usr/bin/env bash

copy_object() {
  if [ $# -ne 3 ]; then
    echo "copy object command requires command type, source, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3 cp "$2" s3://"$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put "$2" s3://"$(dirname "$3")" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure cp "$2" "$MC_ALIAS"/"$(dirname "$3")" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  log 5 "copy object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  return 0
}