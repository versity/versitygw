#!/usr/bin/env bash

allow_public_access() {
  if [ $# -ne 1 ]; then
    log 2 "'allow_public_access' requires bucket name"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/get_public_access_block.sh); then
    log 2 "error getting public access block: $result"
    return 1
  fi
  log 5 "public access block: $(cat "$TEST_FILE_FOLDER/response.txt")"
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/put_public_access_block.sh); then
    log 2 "error getting public access block: $result"
    return 1
  fi
  log 5 "result: $result"
  log 5 "response: $(cat "$TEST_FILE_FOLDER/response.txt")"

  return 1
}