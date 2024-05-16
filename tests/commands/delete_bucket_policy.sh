#!/usr/bin/env bash

delete_bucket_policy() {
  if [[ $# -ne 2 ]]; then
    log 2 "delete bucket policy command requires command type, bucket"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api delete-bucket-policy --bucket "$2") || delete_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate delpolicy "s3://$2") || delete_result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure anonymous set none "$MC_ALIAS/$2") || delete_result=$?
  else
    log 2 "command 'get bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $delete_result -ne 0 ]]; then
    log 2 "error deleting bucket policy: $error"
    return 1
  fi
  return 0
}