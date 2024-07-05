#!/usr/bin/env bash

put_object_retention() {
  record_command "put-object-retention" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "'put object retention' command requires bucket, key, retention mode, retention date"
    return 1
  fi
  error=$(aws --no-verify-ssl s3api put-object-retention --bucket "$1" --key "$2" --retention "{\"Mode\": \"$3\", \"RetainUntilDate\": \"$4\"}" 2>&1) || local put_result=$?
  if [[ $put_result -ne 0 ]]; then
    log 2 "error putting object retention:  $error"
    return 1
  fi
  return 0
}