#!/usr/bin/env bash

# Copyright 2024 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

source ./tests/util/util_mc.sh
source ./tests/logger.sh

create_bucket_invalid_name() {
  if [ $# -ne 1 ]; then
    log 2 "create bucket w/invalid name missing command type"
    return 1
  fi
  local exit_code=0
  if [[ $1 == "aws" ]] || [[ $1 == 's3' ]]; then
    bucket_create_error=$(aws --no-verify-ssl s3 mb "s3://" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    bucket_create_error=$(aws --no-verify-ssl s3api create-bucket --bucket "s3://" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    bucket_create_error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb "s3://" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    bucket_create_error=$(mc --insecure mb "$MC_ALIAS/." 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -eq 0 ]; then
    log 2 "error:  bucket should have not been created but was"
    return 1
  fi
  echo "$bucket_create_error"
}

create_and_check_bucket_invalid_name() {
  if [ $# -ne 1 ]; then
    log 2 "'create_and_check_bucket_invalid_name' requires client"
    return 1
  fi
  if ! create_bucket_invalid_name "$1"; then
    log 2 "error creating bucket with invalid name"
    return 1
  fi

  # shellcheck disable=SC2154
  if [[ "$bucket_create_error" != *"Invalid bucket name "* ]] && [[ "$bucket_create_error" != *"Bucket name cannot"* ]]; then
    log 2 "unexpected error:  $bucket_create_error"
    return 1
  fi
  return 0
}

create_bucket_rest() {
  if ! check_param_count "create_bucket_rest" "bucket name" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/create_bucket.sh 2>&1); then
    log 2 "error creating bucket: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    bucket_create_error="$(cat "$TEST_FILE_FOLDER/result.txt")"
    log 2 "expected '200', was '$result' ($bucket_create_error)"
    return 1
  fi
  return 0
}
