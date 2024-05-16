#!/usr/bin/env bash

get_bucket_acl() {
  if [ $# -ne 2 ]; then
    log 2 "bucket ACL command missing command type, bucket name"
    return 1
  fi
  local exit_code=0
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    acl=$(aws --no-verify-ssl s3api get-bucket-acl --bucket "$2" 2>&1) || exit_code="$?"
  elif [[ $1 == 's3cmd' ]]; then
    acl=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info "s3://$2" 2>&1) || exit_code="$?"
  else
    log 2 "command 'get bucket acl' not implemented for $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "Error getting bucket ACLs: $acl"
    return 1
  fi
  export acl
}