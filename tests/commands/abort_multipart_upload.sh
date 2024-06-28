#!/usr/bin/env bash

abort_multipart_upload() {
  if [ $# -ne 3 ]; then
    log 2 "'abort multipart upload' command requires bucket, key, upload ID"
    return 1
  fi
  if ! error=$(aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" --key "$2" --upload-id "$3" 2>&1); then
    log 2 "Error aborting upload: $error"
    return 1
  fi
  return 0
}

abort_multipart_upload_with_user() {
  if [ $# -ne 5 ]; then
    log 2 "'abort multipart upload' command requires bucket, key, upload ID, username, password"
    return 1
  fi
  if ! abort_multipart_upload_error=$(AWS_ACCESS_KEY_ID="$4" AWS_SECRET_ACCESS_KEY="$5" aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" --key "$2" --upload-id "$3" 2>&1); then
    log 2 "Error aborting upload: $abort_multipart_upload_error"
    export abort_multipart_upload_error
    return 1
  fi
  return 0
}