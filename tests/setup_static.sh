#!/bin/bash

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
source ./tests/util.sh
source ./tests/commands/create_bucket.sh

create_bucket_if_not_exists() {
  if [[ $# -ne 2 ]]; then
    log 2 "create_bucket_if_not_exists command missing command type, name"
    return 1
  fi
  bucket_exists "$1" "$2" || local exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    log 2 "error checking if bucket exists"
    return 1
  fi
  if [[ $exists_result -eq 0 ]]; then
    log 5 "bucket '$2' already exists, skipping"
    return 0
  fi
  if ! create_bucket_object_lock_enabled "$2"; then
    log 2 "error creating bucket"
    return 1
  fi
  log 5 "bucket '$2' successfully created"
  return 0
}

base_setup
if ! create_bucket_if_not_exists "s3api" "$BUCKET_ONE_NAME"; then
  log 2 "error creating static bucket one"
elif ! create_bucket_if_not_exists "s3api" "$BUCKET_TWO_NAME"; then
  log 2 "error creating static bucket two"
fi

# shellcheck disable=SC2034
RECREATE_BUCKETS=false
if ! stop_versity; then
  log 2 "error stopping versity"
fi
