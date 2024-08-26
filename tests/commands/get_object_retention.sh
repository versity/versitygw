#!/usr/bin/env bash

get_object_retention() {
  record_command "get-object-retention" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "'get object retention' command requires bucket, key"
    return 1
  fi
  if ! retention=$(aws --no-verify-ssl s3api get-object-retention --bucket "$1" --key "$2" 2>&1); then
    log 2 "error getting object retention: $retention"
    get_object_retention_error=$retention
    export get_object_retention_error
    return 1
  fi
  return 0
}