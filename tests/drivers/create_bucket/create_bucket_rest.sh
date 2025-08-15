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
source ./tests/drivers/get_object/get_object_rest.sh
source ./tests/drivers/put_bucket_acl/put_bucket_acl_rest.sh
source ./tests/drivers/put_object/put_object_rest.sh
source ./tests/drivers/user.sh

setup_and_create_bucket_and_check_acl() {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "skip bucket create tests for static buckets"
  fi
  if ! check_param_count_v2 "grant env val" 1 $#; then
    return 1
  fi
  test_file="$test_file"
  if ! bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"; then
    log 2 "error cleaning up bucket"
    return 1
  fi

  if ! create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"; then
    log 2 "error creating user"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    # shellcheck disable=SC2154
    id="id=$user_canonical_id"
  else
    id="$user_canonical_id"
  fi
  log 5 "owner: $AWS_ACCESS_KEY_ID"
  log 5 "username=$username, password=$password"
  envs="$1=$id OBJECT_OWNERSHIP=BucketOwnerPreferred"
  log 5 "envs: $envs"
  # shellcheck disable=SC2154
  if ! create_bucket_and_check_acl "$BUCKET_ONE_NAME" "$envs" "$username" "$password" "$user_canonical_id" "$owner_canonical_id"; then
    log 2 "error creating bucket and checking ACL"
    return 1
  fi
  return 0
}

create_bucket_and_check_acl() {
  if ! check_param_count_v2 "bucket name, env vars, username, password, user canonical ID, owner canonical ID" 6 $#; then
    return 1
  fi
  if ! create_bucket_rest_expect_success "$1" "$2"; then
    log 2 "error creating bucket"
    return 1
  fi
  # cross-account changes take more time to propagate
  if [ "$DIRECT" == "true" ]; then
    sleep 10
  fi
  if ! create_test_file "test_file"; then
    log 2 "error creating file"
    return 1
  fi
  local read_acp=false
  local read=false
  local write_acp=false
  local write=false
  if [[ "$2" == *"GRANT_FULL_CONTROL="* ]]; then
    read_acp=true
    read=true
    write_acp=true
    write=true
  elif [[ "$2" == *"GRANT_READ_ACP="* ]]; then
    read_acp=true
  elif [[ "$2" == *"GRANT_READ="* ]]; then
    read=true
  elif [[ "$2" == *"GRANT_WRITE_ACP="* ]]; then
    write_acp=true
  elif [[ "$2" == *"GRANT_WRITE="* ]]; then
    write=true
  fi
  if ! get_bucket_acl_success_or_access_denied "$1" "$3" "$4" "$read_acp"; then
    log 2 "get ACL permissions mismatch"
    return 1
  fi
  if ! put_object_success_or_access_denied "$3" "$4" "$TEST_FILE_FOLDER/test_file" "$1" "test_file" "$write"; then
    log 2 "put object permissions mismatch"
    return 1
  fi
  if ! list_objects_success_or_access_denied "$3" "$4" "$1" "test_file" "$read"; then
    log 2 "list objects permissions mismatch"
    return 1
  fi
  if ! setup_acl "$TEST_FILE_FOLDER/acl-file.txt" "CanonicalUser" "$5" "READ" "$6"; then
    log 2 "error setting up ACL"
    return 1
  fi
  log 5 "acl file: $(cat "$TEST_FILE_FOLDER/acl-file.txt")"
  if ! put_bucket_acl_success_or_access_denied "$1" "$TEST_FILE_FOLDER/acl-file.txt" "$3" "$4" "$write_acp"; then
    log 2 "put ACL permissions mismatch"
    return 1
  fi
  return 0
}