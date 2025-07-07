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

source ./tests/util/util_multipart_abort.sh
source ./tests/util/util_setup.sh

test_s3api_policy_abort_multipart_upload() {
  policy_file="policy_file"
  test_file="test_file"

  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  # shellcheck disable=SC2154
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_policy_with_double_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" \
    "Allow" "$user_id" "s3:PutObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*" \
    "Deny" "$user_id" "s3:AbortMultipartUpload" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success
  # shellcheck disable=SC2154

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run create_multipart_upload_s3api_with_user "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"
  assert_success
  # shellcheck disable=SC2154
  upload_id="$output"

  run check_abort_access_denied "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password"
  assert_success

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$user_id" "s3:AbortMultipartUpload" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run abort_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password"
  assert_success
}

test_s3api_policy_list_multipart_uploads() {
  policy_file="policy_file"
  test_file="test_file"

  run create_test_file "$policy_file"
  assert_success

  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  effect="Allow"
  principal="$user_id"
  action="s3:ListBucketMultipartUploads"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success

  run create_multipart_upload_s3api "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run list_multipart_uploads_with_user "$BUCKET_ONE_NAME" "$username" "$password"
  assert_failure
  assert_output -p "AccessDenied"

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run list_check_multipart_upload_key "$BUCKET_ONE_NAME" "$username" "$password" "$test_file"
  assert_success
}

test_s3api_policy_list_upload_parts() {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1202"
  fi
  policy_file="policy_file"
  test_file="test_file"

  run create_test_files "$policy_file"
  assert_success "error creating test files"

  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success "error setting up bucket and/or large file"

  run setup_user_v2 "user" 1 "$BUCKET_ONE_NAME"
  assert_success
  user_id=${lines[0]}
  username=${lines[1]}
  password=${lines[2]}

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$user_id" "s3:PutObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success "error setting up policy"

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success "error putting policy"

  run create_upload_and_test_parts_listing "$test_file" "$TEST_FILE_FOLDER/$policy_file" "$user_id" "$username" "$password"
  assert_success "error creating upload and testing parts listing"
}
