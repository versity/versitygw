#!/usr/bin/env bash

put_object_legal_hold() {
  record_command "put-object-legal-hold" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'put object legal hold' command requires bucket, key, hold status ('ON' or 'OFF')"
    return 1
  fi
  local error=""
  error=$(aws --no-verify-ssl s3api put-object-legal-hold --bucket "$1" --key "$2" --legal-hold "{\"Status\": \"$3\"}" 2>&1) || local put_hold_result=$?
  if [[ $put_hold_result -ne 0 ]]; then
    log 2 "error putting object legal hold: $error"
    return 1
  fi
  return 0
}