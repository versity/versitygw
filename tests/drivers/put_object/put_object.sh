#!/usr/bin/env bash

# Copyright 2026 Versity Software
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

legal_hold_retention_setup() {
  if ! check_param_count_v2 "bucket name, username, password, test file" 4 $#; then
    return 1
  fi
  if ! setup_user "$2" "$3" "user"; then
    log 2 "error setting up user '$2'"
    return 1
  fi

  if ! create_test_file "$4"; then
    log 2 "error creating test file '$4'"
    return 1
  fi

  if ! setup_bucket_object_lock_enabled_v2 "$1"; then
    log 2 "error creating bucket with object lock enabled"
    return 1
  fi

  if ! change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2"; then
    log 2 "error changing bucket owner"
    return 1
  fi

  if ! put_object_with_user "s3api" "$TEST_FILE_FOLDER/$4" "$1" "$4" "$2" "$3"; then
    log 2 "error putting object with user '$2'"
    return 1
  fi
  return 0
}