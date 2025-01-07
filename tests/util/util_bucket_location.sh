#!/usr/bin/env bash

get_check_bucket_location() {
  if [ $# -ne 2 ]; then
    log 2 "'get_bucket_location' requires client, bucket"
    return 1
  fi
  if ! get_bucket_location "$1" "$2"; then
    log 2 "error getting bucket location"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ $bucket_location != "null" ]] && [[ $bucket_location != "us-east-1" ]]; then
    log 2 "wrong location: '$bucket_location'"
    return 1
  fi
  return 0
}