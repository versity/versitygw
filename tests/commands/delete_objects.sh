#!/usr/bin/env bash

delete_objects() {
  record_command "delete-objects" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'delete-objects' command requires bucket name, two object keys"
    return 1
  fi
  if ! error=$(aws --no-verify-ssl s3api delete-objects --bucket "$1" --delete "{
      \"Objects\": [
        {\"Key\": \"$2\"},
        {\"Key\": \"$3\"}
      ]
    }" 2>&1); then
    log 2 "error deleting objects: $error"
    return 1
  fi
  return 0
}