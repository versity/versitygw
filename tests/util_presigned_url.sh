#!/usr/bin/env bash

source ./tests/commands/create_presigned_url.sh

create_check_presigned_url() {
  if [ $# -ne 4 ]; then
    log 2 "'create_check_presigned_url' requires client, bucket, key, save location"
    return 1
  fi
  if ! create_presigned_url "$1" "$2" "$3"; then
    log 2 "error creating presigned URL"
    return 1
  fi
  if ! error=$(curl -k -v "$presigned_url" -o "$4"); then
    log 2 "error downloading file with curl: $error"
    return 1
  fi
  return 0
}