#!/bin/bash

export VERSITYGW_TEST_ENV=$WORKSPACE/tests/.env.static
# shellcheck source=./.env.static
source "$VERSITYGW_TEST_ENV"
export AWS_PROFILE AWS_REGION BUCKET_ONE_NAME BUCKET_TWO_NAME AWS_ENDPOINT_URL
aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
./tests/setup_static.sh
"$HOME"/bin/bats ./tests/s3_bucket_tests.sh
"$HOME"/bin/bats ./tests/posix_tests.sh
./tests/teardown_static.sh