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

source ./tests/report.sh

# create an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
create_bucket() {
  log 6 "create_bucket"
  if ! check_param_count "create_bucket" "command type, bucket" 2 $#; then
    return 1
  fi

  record_command "create-bucket" "client:$1"
  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(send_command aws --no-verify-ssl s3 mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api create-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    log 5 "s3cmd ${S3CMD_OPTS[*]} --no-check-certificate mb s3://$2"
    error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    error=$(send_command mc --insecure mb "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error creating bucket: $error"
    return 1
  fi
  return 0
}

create_bucket_with_user() {
  log 6 "create_bucket_with_user"
  if ! check_param_count "create_bucket_with_user" "command type, bucket, access ID, secret key" 4 $#; then
    return 1
  fi
  local exit_code=0
  if [[ $1 == "aws" ]] || [[ $1 == "s3api" ]]; then
    error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" send_command aws --no-verify-ssl s3 mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb --access_key="$3" --secret_key="$4" s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    error=$(send_command mc --insecure mb "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error creating bucket: $error"
    return 1
  fi
  return 0
}

create_bucket_object_lock_enabled() {
  log 6 "create_bucket_object_lock_enabled"
  record_command "create-bucket" "client:s3api"
  if ! check_param_count "create_bucket_object_lock_enabled" "bucket" 1 $#; then
    return 1
  fi

  local exit_code=0
  error=$(send_command aws --no-verify-ssl s3api create-bucket --bucket "$1" 2>&1 --object-lock-enabled-for-bucket) || local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    log 2 "error creating bucket: $error"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    sleep 15
  fi
  return 0
}

create_bucket_rest_with_invalid_acl() {
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ACL="public-reads" OBJECT_OWNERSHIP="BucketOwnerPreferred" ./tests/rest_scripts/create_bucket.sh 2>&1); then
    log 2 "error creating bucket: $result"
    return 1
  fi
  if ! check_rest_expected_error "$result" "$TEST_FILE_FOLDER/result.txt" "400" "InvalidArgument" ""; then
    log 2 "error checking XML CreateBucket error"
    return 1
  fi
  return 0
}

create_bucket_rest_expect_error() {
  if ! check_param_count_v2 "bucket name, params, response code, error code, message" 5 $#; then
    return 1
  fi
  env_vars="BUCKET_NAME=$1 $2"
  if ! send_rest_command_expect_error "$env_vars" "./tests/rest_scripts/create_bucket.sh" "$3" "$4" "$5"; then
    log 2 "error sending REST command and checking error"
    return 1
  fi
  return 0
}

create_bucket_rest_expect_success() {
  if ! check_param_count_v2 "bucket name, params" 2 $#; then
    return 1
  fi
  env_vars="BUCKET_NAME=$1 $2"
  if ! send_rest_command_expect_success "$env_vars" "./tests/rest_scripts/create_bucket.sh" "200"; then
    log 2 "error sending REST command and checking error"
    return 1
  fi
  return 0
}
