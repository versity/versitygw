#!/usr/bin/env bash

list_multipart_uploads() {
  record_command "list-multipart-uploads" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "'list multipart uploads' command requires bucket name"
    return 1
  fi
  if ! uploads=$(aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1); then
    log 2 "error listing uploads: $uploads"
    return 1
  fi
}

list_multipart_uploads_with_user() {
  record_command "list-multipart-uploads" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'list multipart uploads' command requires bucket name, username, password"
    return 1
  fi
  if ! uploads=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1); then
    log 2 "error listing uploads: $uploads"
    # shellcheck disable=SC2034
    list_multipart_uploads_error=$uploads
    return 1
  fi
}