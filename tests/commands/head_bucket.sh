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

# params: client, bucket name
# fail for invalid params, return
#   0 - bucket exists
#   1 - bucket does not exist
#   2 - misc error
head_bucket() {
  log 6 "head_bucket"
  record_command "head-bucket" "client:$1"
  if [ $# -ne 2 ]; then
    log 2 "'head_bucket' command requires client, bucket name"
    return 1
  fi
  local exit_code=0
  if [[ $1 == "aws" ]] || [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    bucket_info=$(send_command aws --no-verify-ssl s3api head-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    bucket_info=$(send_command s3cmd --no-check-certificate info "s3://$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    bucket_info=$(send_command mc --insecure stat "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
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
  return 0
}
