#!/bin/bash

if [[ -z "$VERSITYGW_TEST_ENV" ]]; then
  echo "Error:  VERSITYGW_TEST_ENV parameter must be set"
  exit 1
fi
if ! ./tests/run.sh aws; then
  exit 1
fi
if ! ./tests/run.sh aws-posix; then
  exit 1
fi
if ! ./tests/run.sh s3cmd; then
  exit 1
fi
if ! ./tests/run.sh mc; then
  exit 1
fi
if ! ./tests/run.sh -s aws; then
  exit 1
fi
if ! ./tests/run.sh -s aws-posix; then
  exit 1
fi
if ! ./tests/run.sh -s s3cmd; then
  exit 1
fi
if ! ./tests/run.sh -s mc; then
  exit 1
fi
exit 0
