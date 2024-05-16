#!/usr/bin/env bash

source ./tests/util_mc.sh
source ./tests/logger.sh

create_bucket_with_user() {
  if [ $# -ne 4 ]; then
    log 2 "create bucket missing command type, bucket name, access, secret"
    return 1
  fi
  local exit_code=0
  if [[ $1 == "aws" ]]; then
    error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" aws --no-verify-ssl s3 mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    error=$(mc --insecure mb "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error creating bucket: $error"
    export error
    return 1
  fi
  return 0
}

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
    bucket_create_error=$(mc --insecure mb "$MC_ALIAS" 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -eq 0 ]; then
    log 2 "error:  bucket should have not been created but was"
    return 1
  fi
  export bucket_create_error
}
