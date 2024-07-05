#!/usr/bin/env bash

source ./tests/report.sh

head_bucket() {
  record_command "head-bucket" "client:$1"
  if [ $# -ne 2 ]; then
    echo "head bucket command missing command type, bucket name"
    return 1
  fi
  local exit_code=0
  if [[ $1 == "aws" ]] || [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    bucket_info=$(aws --no-verify-ssl s3api head-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    bucket_info=$(s3cmd --no-check-certificate info "s3://$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    bucket_info=$(mc --insecure stat "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error getting bucket info: $bucket_info"
    return 1
  fi
  export bucket_info
  return 0
}
