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
source ./tests/util/util_users.sh
source ./tests/commands/list_buckets.sh

test_admin_user() {
  if [[ $# -ne 1 ]]; then
    fail "test admin user command requires command type"
  fi

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

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if [ "$RECREATE_BUCKETS" == "true" ]; then
    run bucket_cleanup_if_bucket_exists "s3api" "$BUCKET_TWO_NAME"
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

  delete_user "$user_username"
  delete_user "$admin_username"
}

test_create_user_already_exists() {
  if [[ $# -ne 1 ]]; then
    fail "test admin user command requires command type"
  fi

  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"

  run setup_user "$username" "123456" "admin"
  assert_success "error setting up user"

  if create_user "$username" "123456" "admin"; then
    fail "'user already exists' error not returned"
  fi

  delete_user "$username"
}

test_user_user() {
  if [[ $# -ne 1 ]]; then
    fail "test admin user command requires command type"
  fi

  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"

  setup_user "$username" "$password" "user" || fail "error setting up user"
  bucket_cleanup_if_bucket_exists "s3api" "versity-gwtest-user-bucket"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if create_bucket_with_user "s3api" "versity-gwtest-user-bucket" "$username" "$password"; then
    fail "creating bucket with 'user' account failed to return error"
  fi
  # shellcheck disable=SC2154
  [[ $error == *"Access Denied"* ]] || fail "error message '$error' doesn't contain 'Access Denied'"

  create_bucket "s3api" "versity-gwtest-user-bucket" || fail "error creating bucket"

  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "versity-gwtest-user-bucket" "$username" || fail "error changing bucket owner"
  if change_bucket_owner "$username" "$password" "versity-gwtest-user-bucket" "admin"; then
    fail "user shouldn't be able to change bucket owner"
  fi

  list_buckets_with_user "s3api" "$username" "$password" || fail "error listing buckets with user '$username'"
  bucket_found=false
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$BUCKET_ONE_NAME" ]; then
      fail "$BUCKET_ONE_NAME shouldn't show up in 'user' bucket list"
    elif [ "$bucket" == "versity-gwtest-user-bucket" ]; then
      bucket_found=true
    fi
  done
  if [ $bucket_found == false ]; then
    fail "user-owned bucket not found in user list"
  fi

  run delete_bucket "s3api" "versity-gwtest-user-bucket"
  assert_success "failed to delete bucket"
  delete_user "$username"
}

test_userplus_operation() {
  if [[ $# -ne 1 ]]; then
    fail "test admin user command requires command type"
  fi

  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"

  bucket_cleanup_if_bucket_exists "s3api" "versity-gwtest-userplus-bucket"
  setup_user "$username" "$password" "userplus" || fail "error creating user '$username'"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  create_bucket_with_user "s3api" "versity-gwtest-userplus-bucket" "$username" "$password" || fail "error creating bucket with user '$username'"

  list_buckets_with_user "s3api" "$username" "$password" || fail "error listing buckets with user '$username'"
  bucket_found=false
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$BUCKET_ONE_NAME" ]; then
      fail "$BUCKET_ONE_NAME shouldn't show up in 'userplus' bucket list"
    elif [ "$bucket" == "versity-gwtest-userplus-bucket" ]; then
      bucket_found=true
    fi
  done
  if [ $bucket_found == false ]; then
    fail "userplus-owned bucket not found in user list"
  fi

  if change_bucket_owner "$username" "$password" "versity-gwtest-userplus-bucket" "admin"; then
    fail "userplus shouldn't be able to change bucket owner"
  fi

  run delete_bucket "s3api" "versity-gwtest-admin-bucket"
  assert_success "failed to delete bucket"
  delete_user "$username"
}