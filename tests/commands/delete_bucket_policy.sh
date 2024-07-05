#!/usr/bin/env bash

delete_bucket_policy() {
  record_command "delete-bucket-policy" "client:$1"
  if [[ $# -ne 2 ]]; then
    log 2 "delete bucket policy command requires command type, bucket"
    return 1
  fi
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api delete-bucket-policy --bucket "$2" 2>&1) || delete_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate delpolicy "s3://$2" 2>&1) || delete_result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure anonymous set none "$MC_ALIAS/$2" 2>&1) || delete_result=$?
  else
    log 2 "command 'delete bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $delete_result -ne 0 ]]; then
    log 2 "error deleting bucket policy: $error"
    return 1
  fi
  return 0
}

delete_bucket_policy_with_user() {
  record_command "delete-bucket-policy" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'delete bucket policy with user' command requires bucket, username, password"
    return 1
  fi
  if ! delete_bucket_policy_error=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" aws --no-verify-ssl s3api delete-bucket-policy --bucket "$1" 2>&1); then
    log 2 "error deleting bucket policy: $delete_bucket_policy_error"
    export delete_bucket_policy_error
    return 1
  fi
  return 0
}