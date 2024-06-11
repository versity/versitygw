#!/bin/bash

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/commands/create_bucket.sh

create_bucket_if_not_exists() {
  if [[ $# -ne 2 ]]; then
    log 2 "create_bucket_if_not_exists command missing command type, name"
    return 1
  fi
  bucket_exists "$1" "$2" || local exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    log 2 "error checking if bucket exists"
    return 1
  fi
  if [[ $exists_result -eq 0 ]]; then
    log 5 "bucket '$2' already exists, skipping"
    return 0
  fi
  if ! create_bucket_object_lock_enabled "$2"; then
    log 2 "error creating bucket"
    return 1
  fi
  log 5 "bucket '$2' successfully created"
  return 0
}

if ! setup; then
  log 2 "error starting versity to set up static buckets"
  exit 1
fi
if ! create_bucket_if_not_exists "s3api" "$BUCKET_ONE_NAME"; then
  log 2 "error creating static bucket one"
elif ! create_bucket_if_not_exists "s3api" "$BUCKET_TWO_NAME"; then
  log 2 "error creating static bucket two"
fi
if ! teardown; then
  log 2 "error stopping versity"
fi
