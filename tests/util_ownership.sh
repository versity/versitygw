#!/usr/bin/env bash

get_and_check_ownership_controls() {
  if [ $# -ne 2 ]; then
    log 2 "'get_and_check_ownership_controls' missing bucket name, expected result"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OUTPUT_FILE="$TEST_FILE_FOLDER/ownershipControls.txt" ./tests/rest_scripts/get_bucket_ownership_controls.sh); then
    log 2 "error getting bucket ownership controls: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "GetBucketOwnershipControls returned response code: $result, reply:  $(cat "$TEST_FILE_FOLDER/ownershipControls.txt")"
    return 1
  fi
  log 5 "controls: $(cat "$TEST_FILE_FOLDER/ownershipControls.txt")"
  if ! rule=$(xmllint --xpath '//*[local-name()="ObjectOwnership"]/text()' "$TEST_FILE_FOLDER/ownershipControls.txt" 2>&1); then
    log 2 "error getting ownership rule: $rule"
    return 1
  fi
  if [ "$rule" != "$2" ]; then
    log 2 "rule mismatch (expected '$2', actual '$rule')"
    return 1
  fi
  return 0
}

put_bucket_ownership_controls_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'put_bucket_ownership_controls_rest' missing bucket name, ownership"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OWNERSHIP="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_bucket_ownership_controls.sh); then
    log 2 "error putting bucket ownership controls: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "put bucket ownership controls returned code $result: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  return 0
}