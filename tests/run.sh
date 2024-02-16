#!/bin/bash

export VERSITYGW_TEST_ENV=$WORKSPACE/tests/.env.default
# shellcheck source=./.env.default
source "$VERSITYGW_TEST_ENV"
export AWS_PROFILE BUCKET_ONE_NAME BUCKET_TWO_NAME AWS_ENDPOINT_URL
if ! "$HOME"/bin/bats ./tests/s3_bucket_tests.sh; then
  exit 1
fi
if ! "$HOME"/bin/bats ./tests/posix_tests.sh; then
  exit 1
fi