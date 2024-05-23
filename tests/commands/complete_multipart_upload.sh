#!/usr/bin/env bash

complete_multipart_upload() {
  if [[ $# -ne 4 ]]; then
    log 2 "'complete multipart upload' command requires bucket, key, upload ID, parts list"
    return 1
  fi
  log 5 "complete multipart upload id: $3, parts: $4"
  error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2" --upload-id "$3" --multipart-upload '{"Parts": '"$4"'}' 2>&1) || local completed=$?
  if [[ $completed -ne 0 ]]; then
    log 2 "error completing multipart upload: $error"
    return 1
  fi
  log 5 "complete multipart upload error: $error"
  return 0
}