#!/usr/bin/env bash

# param:  bucket name
# fail if params are bad, or bucket exists and user is unable to delete bucket
delete_bucket() {
  log 6 "delete_bucket"
  record_command "delete-bucket" "client:$1"
  assert [ $# -eq 2 ]

  if [[ ( $RECREATE_BUCKETS == "false" ) && (( "$2" == "$BUCKET_ONE_NAME" ) || ( "$2" == "$BUCKET_TWO_NAME" )) ]]; then
    fail "attempt to delete main buckets in static mode"
  fi

  exit_code=0
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 rb s3://"$2") || exit_code=$?
  elif [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api delete-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure rb "$MC_ALIAS/$2" 2>&1) || exit_code=$?
  else
    fail "Invalid command type $1"
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    fi
    fail "error deleting bucket: $error"
  fi
  return 0
}