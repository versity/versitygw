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

source ./tests/setup.sh
source ./tests/util/util_object.sh

delete_bucket_if_exists() {
  if [[ $# -ne 2 ]]; then
    log 2 "delete_bucket_if_exists command missing command type, name"
    return 1
  fi
  bucket_exists "$1" "$2" || local exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    log 2 "error checking if bucket exists"
    return 1
  fi
  if [[ $exists_result -eq 1 ]]; then
    echo "bucket '$2' doesn't exist, skipping"
    return 0
  fi
  if ! delete_bucket_recursive "$1" "$2"; then
    log 2 "error deleting bucket"
    return 1
  fi
  echo "bucket '$2' successfully deleted"
  return 0
}

base_setup
if ! RECREATE_BUCKETS=true delete_bucket_if_exists "s3api" "$BUCKET_ONE_NAME"; then
  log 2 "error deleting static bucket one"
elif ! RECREATE_BUCKETS=true delete_bucket_if_exists "s3api" "$BUCKET_TWO_NAME"; then
  log 2 "error deleting static bucket two"
fi
if ! stop_versity; then
  log 2 "error stopping versity"
fi