#!/usr/bin/env bash

put_bucket_versioning() {
  if [[ $# -ne 3 ]]; then
    log 2 "put bucket versioning command requires command type, bucket name, 'Enabled' or 'Suspended'"
    return 1
  fi
  local put_result=0
  if [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api put-bucket-versioning --bucket "$2" --versioning-configuration "{ \"Status\": \"$3\"}" 2>&1) || put_result=$?
  fi
  if [[ $put_result -ne 0 ]]; then
    log 2 "error putting bucket versioning: $error"
    return 1
  fi
  return 0
}