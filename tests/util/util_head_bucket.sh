#!/usr/bin/env bash

bucket_info_contains_bucket() {
  if [ $# -ne 2 ]; then
    log 2 "'bucket_info_contains_bucket' requires client, bucket"
    return 1
  fi
  if ! head_bucket "mc" "$BUCKET_ONE_NAME"; then
    log 2 "error getting bucket info"
    return 1
  fi

  # shellcheck disable=SC2154
  if [[ "$bucket_info" != *"$BUCKET_ONE_NAME"* ]]; then
    return 1
  fi
  return 0
}