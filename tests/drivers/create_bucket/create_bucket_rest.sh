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

source ./tests/drivers/get_bucket_acl/get_bucket_acl_rest.sh

create_bucket_and_check_acl() {
  if ! check_param_count_v2 "bucket name, env vars, username, password" 4 $#; then
    return 1
  fi
  if ! create_bucket_rest_expect_success "$1" "$2"; then
    log 2 "error creating bucket"
    return 1
  fi
  if ! create_test_file "test_file"; then
    log 2 "error creating file"
    return 1
  fi
  local read_acp=false
  local read=false
  local write_acp=false
  local write=false
  if [[ "$2" == *"GRANT_FULL_CONTROL"* ]]; then
    read_acp=true
    read=true
    write_acp=true
    write=true
  elif [[ "$2" == *"GRANT_READ_ACP"* ]]; then
    read_acp=true
  elif [[ "$2" == *"GRANT_READ"* ]]; then
    read=true
  elif [[ "$2" == *"GRANT_WRITE_ACP"* ]]; then
    write_acp=true
  elif [[ "$2" == *"GRANT_WRITE"* ]]; then
    write=true
  fi
  if ! get_bucket_acl_success_or_access_denied "$1" "$2" "$3" "$read_acp"; then
    log 2 "get ACL permissions mismatch"
    return 1
  fi
  if ! put_object_success_or_access_denied "$3" "$4" "$TEST_FILE_FOLDER/test_file" "$1" "test_file" "$write"; then
    log 2 "put object permissions mismatch"
    return 1
  fi
  if ! get_object_success_or_access_denied "$3" "$4" "$1" "test_file" "$TEST_FILE_FOLDER/test_file_copy" "$read"; then
    log 2 "put object permissions mismatch"
    return 1
  fi
  return 0
}