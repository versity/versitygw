#!/usr/bin/env bash

put_bucket_policy() {
  if [[ $# -ne 3 ]]; then
    log 2 "get bucket policy command requires command type, bucket, policy file"
    return 1
  fi
  local put_policy_result=0
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    policy=$(aws --no-verify-ssl s3api put-bucket-policy --bucket "$2" --policy "file://$3" 2>&1) || put_policy_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    policy=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setpolicy "$3" "s3://$2" 2>&1) || put_policy_result=$?
  elif [[ $1 == 'mc' ]]; then
    policy=$(mc --insecure anonymous set-json "$3" "$MC_ALIAS/$2" 2>&1) || put_policy_result=$?
  else
    log 2 "command 'put bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $put_policy_result -ne 0 ]]; then
    put_bucket_policy_error=$policy
    log 2 "error putting policy: $put_bucket_policy_error"
    export put_bucket_policy_error
    return 1
  fi
  return 0
}