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

source ./tests/env.sh
source ./tests/util/util_object.sh
source ./tests/commands/create_bucket.sh

create_bucket_if_not_exists() {
  if ! check_param_count "create_bucket_if_not_exists" "bucket name" 1 $#; then
    return 1
  fi
  bucket_exists "$1" || local exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    log 2 "error checking if bucket exists"
    return 1
  fi
  if [[ $exists_result -eq 0 ]]; then
    echo "bucket '$1' already exists, skipping"
    return 0
  fi
  if ! create_bucket_object_lock_enabled "$1"; then
    log 2 "error creating bucket"
    return 1
  fi
  echo "bucket '$1' successfully created"
  return 0
}

base_setup
if ! create_bucket_if_not_exists "$BUCKET_ONE_NAME"; then
  log 2 "error creating static bucket one"
elif ! create_bucket_if_not_exists "$BUCKET_TWO_NAME"; then
  log 2 "error creating static bucket two"
fi

# shellcheck disable=SC2034
RECREATE_BUCKETS=false
if ! stop_versity; then
  log 2 "error stopping versity"
fi
