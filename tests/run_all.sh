#!/bin/bash

if [[ -z "$VERSITYGW_TEST_ENV" ]]; then
  echo "Error:  VERSITYGW_TEST_ENV parameter must be set"
  exit 1
fi
if ! ./tests/run.sh; then
  exit 1
fi
if ! ./tests/run_static.sh; then
  exit 1
fi