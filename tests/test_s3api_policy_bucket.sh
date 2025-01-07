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

source ./tests/util/util_acl.sh

test_s3api_policy_delete_bucket_policy() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_file "$policy_file" 0
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:DeleteBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run delete_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_failure

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run delete_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_success
}

test_s3api_policy_get_bucket_acl() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_file "$policy_file" 0
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:GetBucketAcl"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_failure

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_success
}

test_s3api_policy_get_bucket_policy() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_file "$policy_file"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:GetBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success

  run get_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_failure

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run get_and_compare_policy_with_file "$BUCKET_ONE_NAME" "$username" "$password" "$TEST_FILE_FOLDER/$policy_file"
  assert_success
}

test_s3api_policy_get_bucket_tagging() {
  policy_file="policy_file"
  test_file="test_file"
  tag_key="TestKey"
  tag_value="TestValue"

  run create_test_files "$policy_file"
  assert_success "error creating test files"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run setup_user "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success "error creating user '$USERNAME_ONE'"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:GetBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success "error setting up policy"

  run put_bucket_tagging "s3api" "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success "unable to put bucket tagging"

  run get_bucket_tagging_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME"
  assert_failure

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success "error putting policy"

  run get_and_check_bucket_tags_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success "get and check bucket tags failed"
}

test_s3api_policy_put_acl() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_file "$policy_file" 0
  assert_success
  run create_large_file "$test_file"
  assert_success
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$username" "s3:PutBucketAcl" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success
  if [[ $DIRECT == "true" ]]; then
    run put_public_access_block_enable_public_acls "$BUCKET_ONE_NAME"
    assert_success
  fi

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run put_bucket_canned_acl_with_user "$BUCKET_ONE_NAME" "public-read" "$username" "$password"
  assert_success

  run get_check_acl_after_policy "$BUCKET_ONE_NAME"
  assert_success
}

test_s3api_policy_put_bucket_policy() {
  policy_file="policy_file"
  policy_file_two="policy_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_file "$policy_file" 0
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:PutBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run setup_user "$username" "$password" "user"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy_with_user "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" "$username" "$password"
  assert_failure

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file_two" "dummy" "$effect" "$principal" "s3:GetBucketPolicy" "$resource"
  assert_success

  run put_bucket_policy_with_user "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file_two" "$username" "$password"
  assert_success

  run get_and_compare_policy_with_file "$BUCKET_ONE_NAME" "$username" "$password" "$TEST_FILE_FOLDER/$policy_file_two"
  assert_success
}

test_s3api_policy_put_bucket_tagging() {
  policy_file="policy_file"
  tag_key="TestKey"
  tag_value="TestValue"

  run create_test_files "$policy_file"
  assert_success "error creating test files"
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success "error setting up bucket"
  run setup_user "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success "error setting up user"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success "error setting up policy"
  run put_bucket_tagging_with_user "$BUCKET_ONE_NAME" "$tag_key" "$tag_value" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_failure
  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success "error putting policy"
  run put_bucket_tagging_with_user "$BUCKET_ONE_NAME" "$tag_key" "$tag_value" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success "unable to put bucket tagging despite user permissions"

  run get_and_check_bucket_tags "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success
}
