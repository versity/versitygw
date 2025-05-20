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

source ./tests/commands/put_public_access_block.sh
source ./tests/util/util_acl.sh

test_s3api_policy_delete_bucket_policy() {
  policy_file="policy_file"

  run create_test_file "$policy_file" 0
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:DeleteBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run delete_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_failure

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
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

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:GetBucketAcl"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_failure

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_success
}

test_s3api_policy_get_bucket_policy() {
  policy_file="policy_file"

  run create_test_file "$policy_file"
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:GetBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
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

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$user_id" "s3:GetBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success "error setting up policy"

  run put_bucket_tagging "s3api" "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success "unable to put bucket tagging"

  run get_bucket_tagging_with_user "$username" "$password" "$BUCKET_ONE_NAME"
  assert_failure

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success "error putting policy"

  run get_and_check_bucket_tags_with_user "$username" "$password" "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success "get and check bucket tags failed"
}

test_s3api_policy_put_acl() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_file "$policy_file" 0
  assert_success

  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$user_id" "s3:PutBucketAcl" "arn:aws:s3:::$BUCKET_ONE_NAME"
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

  run create_test_file "$policy_file" 0
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:PutBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run put_bucket_policy_with_user "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" "$username" "$password"
  assert_failure

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file_two" "2012-10-17" "$effect" "$principal" "s3:GetBucketPolicy" "$resource"
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
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success "error setting up bucket"

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$user_id" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success "error setting up policy"
  run put_bucket_tagging_with_user "$BUCKET_ONE_NAME" "$tag_key" "$tag_value" "$username" "$password"
  assert_failure
  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success "error putting policy"
  run put_bucket_tagging_with_user "$BUCKET_ONE_NAME" "$tag_key" "$tag_value" "$username" "$password"
  assert_success "unable to put bucket tagging despite user permissions"

  run get_and_check_bucket_tags "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success
}
