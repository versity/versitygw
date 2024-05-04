#!/usr/bin/env bash

copy_object() {
  if [ $# -ne 4 ]; then
    echo "copy object command requires command type, source, bucket, key"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 cp "$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api copy-object --copy-source "$2" --bucket "$3" --key "$4" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate cp "s3://$2" s3://"$3/$4" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure cp "$MC_ALIAS/$2" "$MC_ALIAS/$3/$4" 2>&1) || exit_code=$?
  else
    echo "'copy-object' not implemented for '$1'"
    return 1
  fi
  log 5 "copy object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  return 0
}