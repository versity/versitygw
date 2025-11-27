#!/usr/bin/env bash

# Copyright 2025 Versity Software
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

source ./tests/drivers/head_bucket/head_bucket_rest.sh

# params:  client, bucket name(s)
# return 0 for success, 1 for failure
setup_buckets() {
  if ! check_param_count_gt "minimum of 1 bucket name" 1 $#; then
    return 1
  fi
  for name in "$@"; do
    if ! setup_bucket "$name"; then
      log 2 "error setting up bucket $name"
      return 1
    fi
  done
  return 0
}

# params:  client, bucket name
# return 0 on successful setup, 1 on error
setup_bucket() {
  log 6 "setup_bucket"
  if ! check_param_count "setup_bucket" "bucket name" 1 $#; then
    return 1
  fi

  bucket_exists="true"
  if ! bucket_exists "$1"; then
    if [[ $RECREATE_BUCKETS == "false" ]]; then
      log 2 "When RECREATE_BUCKETS isn't set to \"true\", buckets should be pre-created by user"
      return 1
    fi
    bucket_exists="false"
  fi

  if ! bucket_cleanup_if_bucket_exists "$1" "$bucket_exists"; then
    log 2 "error deleting bucket or contents if they exist"
    return 1
  fi

  log 5 "util.setup_bucket: bucket name: $1"
  if [[ $RECREATE_BUCKETS == "true" ]]; then
    if ! create_bucket_rest_expect_success "$1" ""; then
      log 2 "error creating bucket"
      return 1
    fi
  else
    log 5 "skipping bucket re-creation"
  fi

  if [[ $1 == "s3cmd" ]]; then
    log 5 "putting bucket ownership controls"
    if bucket_exists "$1" && ! put_bucket_ownership_controls "$1" "BucketOwnerPreferred"; then
      log 2 "error putting bucket ownership controls"
      return 1
    fi
  fi
  return 0
}
