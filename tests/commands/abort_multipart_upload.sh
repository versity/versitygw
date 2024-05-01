#!/usr/bin/env bash

abort_multipart_upload() {
  if [ $# -ne 3 ]; then
    echo "command to run abort requires bucket, key, upload ID"
    return 1
  fi

  error=$(aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" --key "$2" --upload-id "$3") || local aborted=$?
  if [[ $aborted -ne 0 ]]; then
    echo "Error aborting upload: $error"
    return 1
  fi
  return 0
}