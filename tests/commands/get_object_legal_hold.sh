#!/usr/bin/env bash

get_object_legal_hold() {
  if [[ $# -ne 2 ]]; then
    log 2 "'get object legal hold' command requires bucket, key"
    return 1
  fi
  record_command "get-object-legal-hold" "client:s3api"
  legal_hold=$(aws --no-verify-ssl s3api get-object-legal-hold --bucket "$1" --key "$2" 2>&1) || local get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting object legal hold: $legal_hold"
    return 1
  fi
  export legal_hold
  return 0
}