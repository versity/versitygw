#!/usr/bin/env bash

get_object_retention() {
  if [[ $# -ne 2 ]]; then
    log 2 "'get object retention' command requires bucket, key"
    return 1
  fi
  retention=$(aws --no-verify-ssl s3api get-object-retention --bucket "$1" --key "$2" 2>&1) || local get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting object retention: $retention"
    return 1
  fi
  export retention
  return 0
}