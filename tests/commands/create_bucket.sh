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
  if [ $# -ne 2 ]; then
    log 2 "create bucket missing command type, bucket name"
    return 1
  fi

  record_command "create-bucket" "client:$1"
  local exit_code=0
  local error
  log 6 "create bucket"
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "aws" ]] || [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api create-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    log 5 "s3cmd ${S3CMD_OPTS[*]} --no-check-certificate mb s3://$2"
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    error=$(mc --insecure mb "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
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
  if [ $# -ne 4 ]; then
    log 2 "create bucket missing command type, bucket name, access, secret"
    return 1
  fi
  local exit_code=0
  if [[ $1 == "aws" ]] || [[ $1 == "s3api" ]]; then
    error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" aws --no-verify-ssl s3 mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb --access_key="$3" --secret_key="$4" s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    error=$(mc --insecure mb "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
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
  record_command "create-bucket" "client:s3api"
  if [ $# -ne 1 ]; then
    log 2 "create bucket missing bucket name"
    return 1
  fi

  local exit_code=0
  error=$(aws --no-verify-ssl s3api create-bucket --bucket "$1" 2>&1 --object-lock-enabled-for-bucket) || local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    log 2 "error creating bucket: $error"
    return 1
  fi
  return 0
}
