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

source ./tests/util/util_file.sh
source ./tests/commands/command.sh
source ./tests/drivers/rest.sh

put_bucket_acl_s3api() {
  log 6 "put_bucket_acl_s3api"
  record_command "put-bucket-acl" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "put bucket acl command requires bucket name, acl file"
    return 1
  fi
  log 5 "bucket name: $1, acls: $(cat "$2")"
  if ! error=$(send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --access-control-policy "file://$2" 2>&1); then
    log 2 "error putting bucket acl: $error"
    return 1
  fi
  return 0
}

put_bucket_acl_s3api_with_user() {
  log 6 "put_bucket_acl_s3api_with_user"
  record_command "put-bucket-acl" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "put bucket acl command requires bucket name, acl file, username, password"
    return 1
  fi
  log 5 "bucket name: $1, acls: $2"
  if ! error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --access-control-policy "file://$2" 2>&1); then
    log 2 "error putting bucket acl: $error"
    return 1
  fi
  return 0
}

reset_bucket_acl() {
  if [ $# -ne 1 ]; then
    log 2 "'reset_bucket_acl' requires bucket name"
    return 1
  fi
  acl_file="acl_file"
  if ! create_test_files "$acl_file"; then
    log 2 "error creating test files"
    return 1
  fi
  # shellcheck disable=SC2154
  if [ "$DIRECT" != "true" ]; then
    if ! setup_acl "$TEST_FILE_FOLDER/$acl_file" "CanonicalUser" "$AWS_ACCESS_KEY_ID" "FULL_CONTROL" "$AWS_ACCESS_KEY_ID"; then
      log 2 "error resetting versitygw ACL"
      return 1
    fi
  elif ! setup_acl "$TEST_FILE_FOLDER/$acl_file" "CanonicalUser" "$AWS_CANONICAL_ID" "FULL_CONTROL" "$AWS_CANONICAL_ID"; then
    log 2 "error resetting direct ACL"
    return 1
  fi
  if ! put_bucket_acl_rest "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$acl_file"; then
    log 2 "error putting bucket acl (s3api)"
    return 1
  fi
  delete_test_files "$acl_file"
  return 0
}

put_bucket_canned_acl_s3cmd() {
  record_command "put-bucket-acl" "client:s3cmd"
  if [[ $# -ne 2 ]]; then
    log 2 "put bucket acl command requires bucket name, permission"
    return 1
  fi
  if ! error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setacl "s3://$1" "$2" 2>&1); then
    log 2 "error putting s3cmd canned ACL:  $error"
    return 1
  fi
  return 0
}

put_bucket_canned_acl() {
  if [[ $# -ne 2 ]]; then
    log 2 "'put bucket canned acl' command requires bucket name, canned ACL"
    return 1
  fi
  record_command "put-bucket-acl" "client:s3api"
  if ! error=$(send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --acl "$2" 2>&1); then
    log 2 "error re-setting bucket acls: $error"
    return 1
  fi
  return 0
}

put_bucket_canned_acl_with_user() {
  if [[ $# -ne 4 ]]; then
    log 2 "'put bucket canned acl with user' command requires bucket name, canned ACL, username, password"
    return 1
  fi
  record_command "put-bucket-acl" "client:s3api"
  if ! error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --acl "$2" 2>&1); then
    log 2 "error re-setting bucket acls: $error"
    return 1
  fi
  return 0
}

put_bucket_acl_rest() {
  if ! check_param_count "put_bucket_acl_rest" "bucket, ACL file" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" ACL_FILE="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/put_bucket_acl.sh); then
    log 2 "error attempting to put bucket acl: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 5 "response returned code: $result (error: $(cat "$TEST_FILE_FOLDER/response.txt")"
    return 1
  fi
  return 0
}

put_canned_acl_rest() {
  if ! check_param_count_v2 "bucket name, canned ACL" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" CANNED_ACL="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/put_bucket_acl.sh); then
    log 2 "error attempting to put bucket acl: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "response code '$result' (message: $(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  return 0
}

put_bucket_acl_rest_canned_invalid() {
  if ! check_param_count_v2 "bucket name, invalid ACL" 2 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" CANNED_ACL="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/put_bucket_acl.sh); then
    log 2 "error attempting to put bucket acl: $result"
    return 1
  fi
  if ! check_rest_expected_error "$result" "$TEST_FILE_FOLDER/response.txt" "400" "InvalidArgument" ""; then
    log 2 "error checking REST response (message: $(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  return 0
}
