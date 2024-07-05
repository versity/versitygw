#!/usr/bin/env bash

get_bucket_ownership_controls() {
  if [[ $# -ne 1 ]]; then
    log 2 "'get bucket ownership controls' command requires bucket name"
    return 1
  fi

  if ! raw_bucket_ownership_controls=$(aws --no-verify-ssl s3api get-bucket-ownership-controls --bucket "$1" 2>&1); then
    log 2 "error getting bucket ownership controls: $raw_bucket_ownership_controls"
    return 1
  fi

  log 5 "Raw bucket Ownership Controls:  $raw_bucket_ownership_controls"
  bucket_ownership_controls=$(echo "$raw_bucket_ownership_controls" | grep -v "InsecureRequestWarning")
  export bucket_ownership_controls
  return 0
}

get_object_ownership_rule() {
  if [[ $# -ne 1 ]]; then
    log 2 "'get object ownership rule' command requires bucket name"
    return 1
  fi
  if ! get_bucket_ownership_controls "$1"; then
    log 2 "error getting bucket ownership controls"
    return 1
  fi
  if ! object_ownership_rule=$(echo "$bucket_ownership_controls" | jq -r ".OwnershipControls.Rules[0].ObjectOwnership" 2>&1); then
    log 2 "error getting object ownership rule: $object_ownership_rule"
    return 1
  fi
  log 5 "object ownership rule: $object_ownership_rule"
  export object_ownership_rule
  return 0
}