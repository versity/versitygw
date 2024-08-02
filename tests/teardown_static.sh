#!/bin/bash

source ./tests/setup.sh
source ./tests/util.sh

if ! setup; then
  log 2 "error starting versity to set up static buckets"
  exit 1
fi
if ! delete_bucket_recursive "s3" "$BUCKET_ONE_NAME"; then
  log 2 "error creating static bucket one"
elif ! delete_bucket_recursive "s3" "$BUCKET_TWO_NAME"; then
  log 2 "error creating static bucket two"
fi
log 4 "buckets deleted successfully"
if ! teardown; then
  log 2 "error stopping versity"
fi