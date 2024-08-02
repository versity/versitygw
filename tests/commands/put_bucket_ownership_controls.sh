#!/usr/bin/env bash

# fail if unable to put bucket ownership controls
put_bucket_ownership_controls() {
  log 6 "put_bucket_ownership_controls"
  record_command "put-bucket-ownership-controls" "client:s3api"
  assert [ $# -eq 2 ]
  run aws --no-verify-ssl s3api put-bucket-ownership-controls --bucket "$1" --ownership-controls="Rules=[{ObjectOwnership=$2}]"
  # shellcheck disable=SC2154
  assert_success "error putting bucket ownership controls: $output"
}