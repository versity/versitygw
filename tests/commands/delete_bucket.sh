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

# param:  bucket name
# fail if params are bad, or bucket exists and user is unable to delete bucket
delete_bucket() {
  log 6 "delete_bucket"
  record_command "delete-bucket" "client:$1"
  if [ $# -ne 2 ]; then
    log 2 "'delete_bucket' command requires client, bucket"
    return 1
  fi

  if [[ ( $RECREATE_BUCKETS == "false" ) && (( "$2" == "$BUCKET_ONE_NAME" ) || ( "$2" == "$BUCKET_TWO_NAME" )) ]]; then
    log 2 "attempt to delete main buckets in static mode"
    return 1
  fi

  exit_code=0
  if [[ $1 == 's3' ]]; then
    error=$(send_command aws --no-verify-ssl s3 rb s3://"$2") || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api delete-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(send_command mc --insecure rb "$MC_ALIAS/$2" 2>&1) || exit_code=$?
  else
    log 2 "Invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    fi
    log 2 "error deleting bucket: $error"
    return 1
  fi
  return 0
}

delete_bucket_rest() {
  if ! check_param_count_gt "bucket, env vars (optional)" 1 $#; then
    return 1
  fi
  env_vars="BUCKET_NAME=$1 $2"
  if ! send_rest_command_expect_success "$env_vars" "./tests/rest_scripts/delete_bucket.sh" "204"; then
    log 2 "error sending REST command and checking error"
    return 1
  fi
  return 0
}