#!/usr/bin/env bash

head_object() {
  record_command "head-object" "client:$1"
  if [ $# -ne 3 ]; then
    log 2 "head-object missing command, bucket name, object name"
    return 2
  fi
  local exit_code=0
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    metadata=$(aws --no-verify-ssl s3api head-object --bucket "$2" --key "$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 's3cmd' ]]; then
    metadata=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info s3://"$2/$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 'mc' ]]; then
    metadata=$(mc --insecure stat "$MC_ALIAS/$2/$3" 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 2
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$metadata" == *"404"* ]] || [[ "$metadata" == *"does not exist"* ]]; then
      log 5 "file doesn't exist ($metadata)"
      return 1
    else
      log 2 "error checking if object exists: $metadata"
      return 2
    fi
  fi
  export metadata
  return 0
}