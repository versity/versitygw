#!/usr/bin/env bash

get_object_attributes() {
  if [[ $# -ne 2 ]]; then
    log 2 "'get object attributes' command requires bucket, key"
    return 1
  fi
  attributes=$(aws --no-verify-ssl s3api get-object-attributes --bucket "$1" --key "$2" --object-attributes "ObjectSize" 2>&1) || local get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error getting object attributes: $attributes"
    return 1
  fi
  attributes=$(echo "$attributes" | grep -v "InsecureRequestWarning")
  log 5 "$attributes"
  export attributes
  return 0
}