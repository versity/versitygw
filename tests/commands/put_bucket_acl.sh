#!/usr/bin/env bash

put_bucket_acl() {
  if [[ $# -ne 3 ]]; then
    log 2 "put bucket acl command requires command type, bucket name, acls or username"
    return 1
  fi
  local error=""
  local put_result=0
  if [[ $1 == 's3api' ]]; then
    log 5 "bucket name: $2, acls: $3"
    error=$(aws --no-verify-ssl s3api put-bucket-acl --bucket "$2" --access-control-policy "file://$3" 2>&1) || put_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setacl "s3://$2" --acl-grant=read:"$3" 2>&1) || put_result=$?
  else
    log 2 "put_bucket_acl not implemented for '$1'"
    return 1
  fi
  if [[ $put_result -ne 0 ]]; then
    log 2 "error putting bucket acl: $error"
    return 1
  fi
  return 0
}

put_bucket_canned_acl() {
  if [[ $# -ne 2 ]]; then
    log 2 "'put bucket canned acl' command requires bucket name, canned ACL"
    return 1
  fi
  if ! error=$(aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --acl "$2"); then
    log 2 "error resetting bucket acls: $error"
    return 1
  fi
  return 0
}