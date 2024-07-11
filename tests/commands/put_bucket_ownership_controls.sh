#!/usr/bin/env bash

put_bucket_ownership_controls() {
  if [[ $# -ne 2 ]]; then
    log 2 "'put bucket ownership controls' command requires bucket name, control"
    return 1
  fi
  if ! controls_error=$(aws --no-verify-ssl s3api put-bucket-ownership-controls --bucket "$1" \
      --ownership-controls="Rules=[{ObjectOwnership=$2}]" 2>&1); then
    log 2 "error putting bucket ownership controls: $controls_error"
    return 1
  fi
  return 0
}