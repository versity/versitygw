#!/usr/bin/env bash

put_bucket_policy() {
  if [[ $# -ne 3 ]]; then
    echo "get bucket policy command requires command type, bucket, policy file"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    policy=$(aws --no-verify-ssl s3api put-bucket-policy --bucket "$2" --policy "file://$3") || get_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    policy=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setpolicy "$3" "s3://$2") || get_result=$?
  elif [[ $1 == 'mc' ]]; then
    policy=$(mc --insecure anonymous set-json "$3" "$MC_ALIAS/$2")
  else
    echo "command 'put bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $get_result -ne 0 ]]; then
    echo "error putting policy: $policy"
    return 1
  fi
  return 0
}