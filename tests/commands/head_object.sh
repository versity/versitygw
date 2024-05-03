#!/usr/bin/env bash

head_object() {
  if [ $# -ne 3 ]; then
    echo "head-object missing command, bucket name, object name"
    return 2
  fi
  local exit_code=0
  local error=""
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3api head-object --bucket "$2" --key "$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info s3://"$2/$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure stat "$MC_ALIAS/$2/$3" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 2
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"404"* ]] || [[ "$error" == *"does not exist"* ]]; then
      return 1
    else
      echo "error checking if object exists: $error"
      return 2
    fi
  fi
  return 0
}