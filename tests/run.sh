#!/bin/bash

VERSITYGW_TEST_ENV=$WORKSPACE/tests/.env.default "$HOME"/bin/bats ./tests/s3_bucket_tests.sh
VERSITYGW_TEST_ENV=$WORKSPACE/tests/.env.default "$HOME"/bin/bats ./tests/posix_tests.sh