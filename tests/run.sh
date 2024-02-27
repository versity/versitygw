#!/bin/bash

if [[ -z "$VERSITYGW_TEST_ENV" ]]; then
  echo "Error:  VERSITYGW_TEST_ENV parameter must be set"
  exit 1
fi
export RECREATE_BUCKETS=true
if ! "$HOME"/bin/bats ./tests/s3_bucket_tests.sh; then
  exit 1
fi
if ! "$HOME"/bin/bats ./tests/posix_tests.sh; then
  exit 1
fi
if ! "$HOME"/bin/bats ./tests/s3cmd_tests.sh; then
  exit 1
fi