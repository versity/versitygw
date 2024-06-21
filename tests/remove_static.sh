#!/bin/bash

source ./tests/setup.sh
source ./tests/util.sh

delete_bucket_if_exists() {
  if [[ $# -ne 2 ]]; then
    log 2 "delete_bucket_if_exists command missing command type, name"
    return 1
  fi
  bucket_exists "$1" "$2" || local exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    log 2 "error checking if bucket exists"
    return 1
  fi
  if [[ $exists_result -eq 1 ]]; then
    log 5 "bucket '$2' doesn't exist, skipping"
    return 0
  fi
  if ! delete_bucket_recursive "$1" "$2"; then
    log 2 "error deleting bucket"
    return 1
  fi
  log 5 "bucket '$2' successfully deleted"
  return 0
}

if ! setup; then
  log 2 "error starting versity to set up static buckets"
  exit 1
fi
if ! delete_bucket_if_exists "s3api" "$BUCKET_ONE_NAME"; then
  log 2 "error deleting static bucket one"
elif ! delete_bucket_if_exists "s3api" "$BUCKET_TWO_NAME"; then
  log 2 "error deleting static bucket two"
fi
if ! teardown; then
  log 2 "error stopping versity"
fi