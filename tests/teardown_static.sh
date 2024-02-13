#!/bin/bash

source ./tests/setup.sh
setup
aws s3 rb s3://"$BUCKET_ONE_NAME"
aws s3 rb s3://"$BUCKET_TWO_NAME"
teardown