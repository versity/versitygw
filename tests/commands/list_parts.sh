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

list_parts_with_user() {
  if [ $# -ne 5 ]; then
    log 2 "'list_parts_with_user' requires username, password, bucket, key, upload ID"
    return 1
  fi
  record_command 'list-parts' 'client:s3api'
  if ! listed_parts=$(AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" aws --no-verify-ssl s3api list-parts --bucket "$3" --key "$4" --upload-id "$5" 2>&1); then
    log 2 "Error listing multipart upload parts: $listed_parts"
    return 1
  fi
}