#!/usr/bin/env bash

put_public_access_block() {
  if [[ $# -ne 2 ]]; then
    log 2 "'put_public_access_block' command requires bucket, access block list"
    return 1
  fi
  if ! error=$(aws --no-verify-ssl s3api put-public-access-block --bucket "$1" --public-access-block-configuration "$2"); then
    log 2 "error updating public access block: $error"
    return 1
  fi
}

put_public_access_block_enable_public_acls() {
  if [[ $# -ne 1 ]]; then
    log 2 "command requires bucket"
    return 1
  fi
  if ! put_public_access_block "$1" "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=true,RestrictPublicBuckets=true"; then
    log 2 "error putting public acccess block"
    return 1
  fi
  return 0
}

put_public_access_block_disable_public_acls() {
  if [[ $# -ne 1 ]]; then
    log 2 "command requires bucket"
    return 1
  fi
  if ! put_public_access_block "$1" "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"; then
    log 2 "error putting public access block"
    return 1
  fi
  return 0
}

