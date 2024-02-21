#!/usr/bin/env bash

setup_two_buckets() {
  setup_bucket "$BUCKET_ONE_NAME" || local setup_result_one=$?
  if [[ $setup_result_one -eq 0 ]]; then
    return 1
  fi
  setup_bucket "$BUCKET_TWO_NAME" || local setup_result_two=$?
  if [[ $setup_result_two -eq 0 ]]; then
    return 1
  fi
  return 0
}