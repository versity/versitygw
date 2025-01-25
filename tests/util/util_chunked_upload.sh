#!/usr/bin/env bash

attempt_seed_signature_without_content_length() {
  if [ "$#" -ne 3 ]; then
    log 2 "'attempt_seed_signature_without_content_length' requires bucket name, key, data file"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" CONTENT_ENCODING="aws-chunked" BUCKET_NAME="$1" OBJECT_KEY="$2" DATA_FILE="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object.sh); then
    log 2 "error putting object: $result"
    return 1
  fi
  if [ "$result" != 411 ]; then
    log 2 "expected '411', actual '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}