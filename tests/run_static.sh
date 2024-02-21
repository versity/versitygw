#!/bin/bash

export VERSITYGW_TEST_ENV=$WORKSPACE/tests/.env.static
# shellcheck source=./.env.static
source "$VERSITYGW_TEST_ENV"
export AWS_PROFILE BUCKET_ONE_NAME BUCKET_TWO_NAME AWS_ENDPOINT_URL
result=0
./tests/setup_static.sh
if ! "$HOME"/bin/bats ./tests/s3_bucket_tests.sh; then
  result=1
fi
if ! "$HOME"/bin/bats ./tests/posix_tests.sh; then
  result=1
fi
./tests/teardown_static.sh
exit $result