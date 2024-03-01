#!/bin/bash

if [[ -z "$VERSITYGW_TEST_ENV" ]]; then
  echo "Error:  VERSITYGW_TEST_ENV parameter must be set"
  exit 1
fi
result=0
export RECREATE_BUCKETS=false
./tests/setup_static.sh
if ! "$HOME"/bin/bats ./tests/s3_bucket_tests.sh; then
  result=1
fi
if ! "$HOME"/bin/bats ./tests/posix_tests.sh; then
  result=1
fi
if ! "$HOME"/bin/bats ./tests/s3cmd_tests.sh; then
  result=1
fi
./tests/teardown_static.sh
exit $result