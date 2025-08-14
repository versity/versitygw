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

source ./tests/rest_scripts/rest.sh

send_not_implemented_expect_failure() {
  if [ $(($# % 2)) -ne 0 ]; then
    log 2 "'send_not_implemented_expect_failure' param count must be multiple of 2 (key/value pairs)"
    return 1
  fi
  if ! curl_command=$(go run ./tests/rest_scripts/generate_command.go -awsAccessKeyId "$AWS_ACCESS_KEY_ID" -awsSecretAccessKey "$AWS_SECRET_ACCESS_KEY" -url "$AWS_ENDPOINT_URL" "$@" 2>&1); then
    log 2 "error: $curl_command"
    return 1
  fi
  local full_command="send_command $curl_command"
  log 5 "full command: $full_command"
  if ! result=$(eval "${full_command[*]}" 2>&1); then
    log 3 "error sending command: $result"
    return 1
  fi
  log 5 "result: $result"
  echo -n "$result" > "$TEST_FILE_FOLDER/result.txt"
  if ! check_rest_expected_header_error "$TEST_FILE_FOLDER/result.txt" "501" "NotImplemented"; then
    log 2 "error checking expected header error"
    return 1
  fi
  return 0
}

test_not_implemented_expect_failure() {
  if ! check_param_count_v2 "bucket, query, method" 3 $#; then
    return 1
  fi
  if ! setup_bucket "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! send_not_implemented_expect_failure "-bucketName" "$1" "-query" "$2" "-method" "$3"; then
    log 2 "error with command that should be \"not implemented\""
    return 1
  fi
  return 0
}