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

test_s3api_policy_allow_deny() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_files "$policy_file" "$test_file"
  assert_success

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run setup_policy_with_double_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" \
    "Deny" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file" \
    "Allow" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_delete() {
  policy_file="policy_file"
  test_file_one="test_file_one"
  test_file_two="test_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_files "$test_file_one" "$test_file_two" "$policy_file"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:DeleteObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two"

  setup_user "$username" "$password" "user" || fail "error creating user"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  log 5 "Policy: $(cat "$TEST_FILE_FOLDER/$policy_file")"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" || fail "error putting policy"

  put_object "s3api" "$TEST_FILE_FOLDER/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one" || fail "error copying object one"
  put_object "s3api" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object two"
  if delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_one" "$username" "$password"; then
    fail "able to delete object despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$delete_object_error" == *"Access Denied"* ]] || fail "invalid delete object error: $delete_object_error"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$username" "$password" || fail "error deleting object despite permissions"
}

test_s3api_policy_deny() {
  policy_file="policy_file"
  test_file_one="test_file_one"
  test_file_two="test_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_files "$test_file_one" "$test_file_two" "$policy_file"
  assert_success

  setup_user "$username" "$password" "user" || fail "error creating user"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  setup_policy_with_double_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" \
    "Deny" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two" \
    "Allow" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*"

  log 5 "Policy: $(cat "$TEST_FILE_FOLDER/$policy_file")"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" || fail "error putting policy"
  put_object "s3api" "$TEST_FILE_FOLDER/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one" || fail "error copying object one"
  put_object "s3api" "$TEST_FILE_FOLDER/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object two"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_one" "$TEST_FILE_FOLDER/$test_file_one-copy" "$username" "$password" || fail "error getting object"

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$TEST_FILE_FOLDER/$test_file_two-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_file_wildcard() {
  policy_file="policy_file_one"
  policy_file_two="policy_file_two"
  policy_file_three="policy_fil"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_files "$policy_file" "$policy_file_two" "$policy_file_three"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/policy_file*"

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success
  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$policy_file" "$BUCKET_ONE_NAME" "$policy_file"
  assert_success
  run put_object "s3api" "$TEST_FILE_FOLDER/$policy_file_two" "$BUCKET_ONE_NAME" "$policy_file_two"
  assert_success
  run put_object "s3api" "$TEST_FILE_FOLDER/$policy_file_three" "$BUCKET_ONE_NAME" "$policy_file_three"
  assert_success

  run download_and_compare_file_with_user "s3api" "$TEST_FILE_FOLDER/$policy_file" "$BUCKET_ONE_NAME" "$policy_file" "$TEST_FILE_FOLDER/$policy_file-copy" "$username" "$password"
  assert_success

  run download_and_compare_file_with_user "s3api" "$TEST_FILE_FOLDER/$policy_file_two" "$BUCKET_ONE_NAME" "$policy_file_two" "$TEST_FILE_FOLDER/$policy_file_two-copy" "$username" "$password"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$policy_file_three" "$TEST_FILE_FOLDER/$policy_file_three" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_folder_wildcard() {
  policy_file="policy_file"
  test_folder="test_folder"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_folder "$test_folder"
  assert_success

  run create_test_files "$test_folder/$test_file" "$policy_file"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file"
  assert_success

  run download_and_compare_file_with_user "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_specific_file() {
  policy_file="policy_file"
  test_file="test_file"
  test_file_two="test_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_files "$policy_file" "$test_file" "$test_file_two"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/test_file"

  setup_user "$username" "$password" "user" || fail "error creating user"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" || fail "error putting policy"

  put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "error copying object"
  put_object "s3api" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object"

  run download_and_compare_file_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$TEST_FILE_FOLDER/$test_file_two-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_with_user() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE
  test_file="test_file"

  log 5 "username: $USERNAME_ONE, password: $PASSWORD_ONE"
  run create_test_files "$test_file" "$policy_file"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run setup_user "$username" "$password" "user"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run download_and_compare_file_with_user "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_invalid_action() {
  policy_file="policy_file"

  run create_test_file "$policy_file"
  assert_success

  effect="Allow"
  principal="*"
  action="s3:GetObjectt"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"

  # shellcheck disable=SC2154
  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run check_for_empty_policy "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run put_and_check_for_malformed_policy "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success
}

test_s3api_policy_put_wildcard() {
  policy_file="policy_file"
  test_folder="test_folder"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_folder "$test_folder"
  assert_success

  run create_test_files "$test_folder/$test_file" "$policy_file"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:PutObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  log 5 "Policy: $(cat "$TEST_FILE_FOLDER/$policy_file")"
  setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" || fail "error putting policy"
  if put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"; then
    fail "able to put object despite not being allowed"
  fi
  # shellcheck disable=SC2154
  [[ "$put_object_error" == *"Access Denied"* ]] || fail "invalid put object error: $put_object_error"
  put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$username" "$password" || fail "error putting file despite policy permissions"

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_folder/$test_file-copy" "$username" "$password"
  assert_success

  download_and_compare_file "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$TEST_FILE_FOLDER/$test_file-copy" || fail "files don't match"
}

test_s3api_policy_two_principals() {
  policy_file="policy_file"
  test_file="test_file"

  run create_test_files "$test_file" "$policy_file"
  assert_success "error creating test files"
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success "error setting up bucket $BUCKET_ONE_NAME"
  run setup_user "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success "error setting up user $USERNAME_ONE"
  run setup_user "$USERNAME_TWO" "$PASSWORD_TWO" "user"
  assert_success "error setting up user $USERNAME_TWO"

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success "error adding object to bucket"
  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_one" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_failure "able to get object with user $USERNAME_ONE despite lack of permission"

  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_two" "$USERNAME_TWO" "$PASSWORD_TWO"
  assert_failure "able to get object with user $USERNAME_TWO despite lack of permission"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "Allow" "[\"$USERNAME_ONE\", \"$USERNAME_TWO\"]" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success "error setting up policy"

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success "error putting policy"
  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_one" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success "error getting object with user $USERNAME_ONE"
  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_two" "$USERNAME_TWO" "$PASSWORD_TWO"
  assert_success "error getting object with user $USERNAME_TWO"
}
