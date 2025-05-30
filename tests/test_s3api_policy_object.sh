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

source ./tests/util/util_delete_object.sh
source ./tests/util/util_setup.sh

test_s3api_policy_allow_deny() {
  policy_file="policy_file"
  test_file="test_file"

  run create_test_files "$policy_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  # shellcheck disable=SC2154
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run setup_policy_with_double_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" \
    "Deny" "$user_id" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file" \
    "Allow" "$user_id" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"
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

  run create_test_files "$policy_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:DeleteObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two"

  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$test_file_one" "$test_file_two"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  log 5 "Policy: $(cat "$TEST_FILE_FOLDER/$policy_file")"
  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run block_delete_object_without_permission "$BUCKET_ONE_NAME" "$test_file_one" "$username" "$password"
  assert_success

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$username" "$password"
  assert_success
}

test_s3api_policy_deny() {
  policy_file="policy_file"
  test_file_one="test_file_one"
  test_file_two="test_file_two"

  run create_test_files "$policy_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$test_file_one" "$test_file_two"
  assert_success

  run setup_policy_with_double_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" \
    "Deny" "$user_id" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two" \
    "Allow" "$user_id" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success

  log 5 "Policy: $(cat "$TEST_FILE_FOLDER/$policy_file")"
  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one"
  assert_success
  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_one" "$TEST_FILE_FOLDER/$test_file_one-copy" "$username" "$password"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$TEST_FILE_FOLDER/$test_file_two-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_file_wildcard() {
  policy_file="policy_file_one"
  policy_file_two="policy_file_two"
  policy_file_three="policy_fil"

  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$policy_file_two" "$policy_file_three"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/policy_file*"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success
  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$policy_file" "$BUCKET_ONE_NAME" "$policy_file"
  assert_success
  run put_object "s3api" "$TEST_FILE_FOLDER/$policy_file_two" "$BUCKET_ONE_NAME" "$policy_file_two"
  assert_success
  run put_object "s3api" "$TEST_FILE_FOLDER/$policy_file_three" "$BUCKET_ONE_NAME" "$policy_file_three"
  assert_success

  run download_and_compare_file_with_user "$TEST_FILE_FOLDER/$policy_file" "$BUCKET_ONE_NAME" "$policy_file" "$TEST_FILE_FOLDER/$policy_file-copy" "$username" "$password"
  assert_success

  run download_and_compare_file_with_user "$TEST_FILE_FOLDER/$policy_file_two" "$BUCKET_ONE_NAME" "$policy_file_two" "$TEST_FILE_FOLDER/$policy_file_two-copy" "$username" "$password"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$policy_file_three" "$TEST_FILE_FOLDER/$policy_file_three" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_folder_wildcard() {
  policy_file="policy_file"
  test_folder="test_folder"
  test_file="test_file"

  run create_test_folder "$test_folder"
  assert_success

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_folder/$test_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file"
  assert_success

  run download_and_compare_file_with_user "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_specific_file() {
  policy_file="policy_file"
  test_file="test_file"
  test_file_two="test_file_two"

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$test_file" "$test_file_two"
  assert_success

  effect="Allow"
  principal="$user_id"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/test_file"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run download_and_compare_file_with_user "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$TEST_FILE_FOLDER/$test_file_two-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_get_object_with_user() {
  test_file="test_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success

  policy_file="policy_file"
  effect="Allow"
  principal="$user_id"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run download_and_compare_file_with_user "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" "$username" "$password"
  assert_success
}

test_s3api_policy_invalid_action() {
  policy_file="policy_file"
  effect="Allow"
  principal="*"
  action="s3:GetObjectt"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"

  # shellcheck disable=SC2154
  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
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

  run create_test_folder "$test_folder"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  # shellcheck disable=SC2154
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_folder/$test_file"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$user_id" "s3:PutObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_failure
  # shellcheck disable=SC2154
  assert_output -p "AccessDenied"

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$username" "$password"
  assert_success

  run verify_user_cant_get_object "s3api" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_folder/$test_file-copy" "$username" "$password"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

test_s3api_policy_two_principals() {
  policy_file="policy_file"
  test_file="test_file"

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id_one=${lines[0]}
  username_one=${lines[1]}
  password_one=${lines[2]}

  run setup_user_v2 "user" 2 "$BUCKET_ONE_NAME"
  assert_success
  user_id_two=${lines[0]}
  username_two=${lines[1]}
  password_two=${lines[2]}

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_one" "$username_one" "$password_one"
  assert_failure
  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_two" "$username_two" "$password_two"
  assert_failure

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$user_id_one,$user_id_two" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success
  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_one" "$username_one" "$password_one"
  assert_success
  run get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/copy_two" "$username_two" "$password_two"
  assert_success
}
