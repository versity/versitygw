#!/usr/bin/env bash

list_multipart_uploads() {
  if [[ $# -ne 1 ]]; then
    log 2 "'list multipart uploads' command requires bucket name"
    return 1
  fi
  if ! uploads=$(aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1); then
    log 2 "error listing uploads: $uploads"
    return 1
  fi
  export uploads
}

list_multipart_uploads_with_user() {
  if [[ $# -ne 3 ]]; then
    log 2 "'list multipart uploads' command requires bucket name, username, password"
    return 1
  fi
  if ! uploads=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1); then
    log 2 "error listing uploads: $uploads"
    list_multipart_uploads_error=$uploads
    export list_multipart_uploads_error
    return 1
  fi
  export uploads
}