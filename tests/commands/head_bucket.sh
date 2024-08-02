#!/usr/bin/env bash

source ./tests/report.sh

# params: client, bucket name
# fail for invalid params, return
#   0 - bucket exists
#   1 - bucket does not exist
#   2 - misc error
head_bucket() {
  log 6 "head_bucket"
  record_command "head-bucket" "client:$1"
  assert [ $# -eq 2 ]
  local exit_code=0
  if [[ $1 == "aws" ]] || [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    bucket_info=$(aws --no-verify-ssl s3api head-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    bucket_info=$(s3cmd --no-check-certificate info "s3://$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    bucket_info=$(mc --insecure stat "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    fail "invalid command type $1"
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$bucket_info" == *"404"* ]] || [[ "$bucket_info" == *"does not exist"* ]]; then
      return 1
    fi
    log 2 "error getting bucket info: $bucket_info"
    return 2
  fi
  export bucket_info
  return 0
}
