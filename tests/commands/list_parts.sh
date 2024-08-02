#!/usr/bin/env bash

list_parts() {
  if [[ $# -ne 3 ]]; then
    log 2 "'list-parts' command requires bucket, key, upload ID"
    return 1
  fi
  record_command "list-parts" "client:s3api"
  if ! listed_parts=$(aws --no-verify-ssl s3api list-parts --bucket "$1" --key "$2" --upload-id "$3" 2>&1); then
    log 2 "Error listing multipart upload parts: $listed_parts"
    return 1
  fi
}