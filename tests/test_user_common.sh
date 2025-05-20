#!/usr/bin/env bats

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
source ./tests/util/util_create_bucket.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_object.sh
source ./tests/util/util_setup.sh
source ./tests/util/util_users.sh
source ./tests/commands/list_buckets.sh

test_admin_user() {
  admin_username="$USERNAME_ONE"
  admin_password="$PASSWORD_ONE"
  user_username="$USERNAME_TWO"
  user_password="$PASSWORD_TWO"

  run setup_user "$admin_username" "$admin_password" "admin"
  assert_success

  if user_exists "$user_username"; then
    run delete_user "$user_username"
    assert_success
  fi
  run create_user_with_user "$admin_username" "$admin_password" "$user_username" "$user_password" "user"
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  if [ "$RECREATE_BUCKETS" == "true" ]; then
    run bucket_cleanup_if_bucket_exists "$BUCKET_TWO_NAME"
    assert_success
    run create_bucket_with_user "s3api" "$BUCKET_TWO_NAME" "$admin_username" "$admin_password"
    assert_success
  else
    run change_bucket_owner "$admin_username" "$admin_password" "$BUCKET_TWO_NAME" "$admin_username"
    assert_success
  fi

  run list_and_check_buckets_with_user "s3api" "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME" "$admin_username" "$admin_password"
  assert_success

  run change_bucket_owner "$admin_username" "$admin_password" "$BUCKET_TWO_NAME" "$user_username"
  assert_success
}

test_create_user_already_exists() {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"

  run setup_user "$username" "$password" "admin"
  assert_success

  run create_user_versitygw "$username" "$password" "admin"
  assert_failure
}

test_user_user() {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "test not valid for static buckets"
  fi

  run setup_user_v2 "user" "1" "$BUCKET_ONE_NAME"
  assert_success
  # shellcheck disable=SC2154
  username="${lines[1]}"
  password="${lines[2]}"
  log 5 "username: $username, password: $password"

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  if [ "$RECREATE_BUCKETS" == "true" ]; then
    run bucket_cleanup_if_bucket_exists "$BUCKET_TWO_NAME"
    assert_success
    run create_bucket "s3api" "$BUCKET_TWO_NAME"
    assert_success
  else
    run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_TWO_NAME" "$AWS_ACCESS_KEY_ID"
    assert_success
  fi

  run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_TWO_NAME" "$username"
  assert_success

  run change_bucket_owner "$username" "$password" "$BUCKET_TWO_NAME" "$AWS_ACCESS_KEY_ID"
  assert_failure
  assert_output -p "AccessDenied"

  run list_and_check_buckets_omit_without_permission "$username" "$password" "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success
}

test_userplus_operation() {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"

  run setup_bucket_and_user "$BUCKET_ONE_NAME" "$username" "$password" "userplus"
  assert_success

  if [ "$RECREATE_BUCKETS" == "true" ]; then
    run bucket_cleanup_if_bucket_exists "$BUCKET_TWO_NAME"
    assert_success
    run create_bucket_with_user "s3api" "$BUCKET_TWO_NAME" "$username" "$password"
    assert_success
  else
    run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_TWO_NAME" "$username"
    assert_success
  fi

  run list_and_check_buckets_omit_without_permission "$username" "$password" "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  run change_bucket_owner "$username" "$password" "$BUCKET_TWO_NAME" "admin"
  assert_failure
}