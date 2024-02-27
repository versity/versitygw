#!/bin/bash

source ./tests/setup.sh
setup
aws --no-verify-ssl s3 rb s3://"$BUCKET_ONE_NAME"
aws --no-verify-ssl s3 rb s3://"$BUCKET_TWO_NAME"
teardown