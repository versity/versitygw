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
  if [[ ( "$2" == *"GRANT_FULL_CONTROL"* ) || ( "$2" == *"GRANT_READ_ACP"* ) ]]; then
    read_acp=true
  fi
  if ! get_bucket_acl_success_or_access_denied "$1" "$2 AWS_ACCESS_KEY_ID=$3 AWS_SECRET_ACCESS_KEY=$4" "$read_acp"; then
    log 2 "error getting bucket acl"
    return 1
  fi
  return 0
}