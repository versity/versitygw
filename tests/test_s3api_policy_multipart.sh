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

test_s3api_policy_abort_multipart_upload() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE

  run create_test_file "$policy_file"
  assert_success

  run create_large_file "$test_file"
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if [[ $DIRECT == "true" ]]; then
    setup_user_direct "$username" "user" "$BUCKET_ONE_NAME" || fail "error setting up direct user $username"
    principal="{\"AWS\": \"arn:aws:iam::$DIRECT_AWS_USER_ID:user/$username\"}"
    # shellcheck disable=SC2154
    username=$key_id
    # shellcheck disable=SC2154
    password=$secret_key
  else
    password=$PASSWORD_ONE
    setup_user "$username" "$password" "user" || fail "error setting up user $username"
    principal="\"$username\""
  fi

  setup_policy_with_double_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" \
    "Allow" "$principal" "s3:PutObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*" \
    "Deny" "$principal" "s3:AbortMultipartUpload" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" || fail "error putting first policy"

  create_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "error creating multipart upload"
  # shellcheck disable=SC2154
  if abort_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password"; then
    fail "abort multipart upload succeeded despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$abort_multipart_upload_error" == *"AccessDenied"* ]] || fail "unexpected abort error:  $abort_multipart_upload_error"

  setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$principal" "s3:AbortMultipartUpload" "arn:aws:s3:::$BUCKET_ONE_NAME/*"

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" || fail "error putting policy"
  abort_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password" || fail "error aborting multipart upload despite permissions"
}

test_s3api_policy_list_multipart_uploads() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run create_test_file "$policy_file"
  assert_success

  run create_large_file "$test_file"
  assert_success

  effect="Allow"
  principal="$username"
  action="s3:ListBucketMultipartUploads"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"
  setup_user "$username" "$password" "user" || fail "error creating user"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  get_bucket_policy "s3api" "$BUCKET_ONE_NAME" || fail "error getting bucket policy"
  # shellcheck disable=SC2154
  log 5 "BUCKET POLICY: $bucket_policy"
  get_bucket_acl "s3api" "$BUCKET_ONE_NAME" || fail "error getting bucket ACL"
  # shellcheck disable=SC2154
  log 5 "ACL: $acl"
  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success "failed to set up policy"
  run create_multipart_upload "$BUCKET_ONE_NAME" "$test_file"
  assert_success "failed to create multipart upload"
  if list_multipart_uploads_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "able to list multipart uploads despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$list_multipart_uploads_error" == *"Access Denied"* ]] || fail "invalid list multipart uploads error: $list_multipart_uploads_error"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file" || fail "error putting policy"
  list_multipart_uploads_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error listing multipart uploads"
  # shellcheck disable=SC2154
  log 5 "$uploads"
  upload_key=$(echo "$uploads" | grep -v "InsecureRequestWarning" | jq -r ".Uploads[0].Key" 2>&1) || fail "error parsing upload key from uploads message: $upload_key"
  [[ $upload_key == "$test_file" ]] || fail "upload key doesn't match file marked as being uploaded"
}

test_s3api_policy_list_upload_parts() {
  policy_file="policy_file"
  test_file="test_file"

  run create_test_files "$policy_file"
  assert_success "error creating test files"

  run create_large_file "$test_file"
  assert_success "error creating large file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success "error setting up bucket"

  run setup_user "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success "error creating user '$USERNAME_ONE'"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:PutObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success "error setting up policy"

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success "error putting policy"

  run create_upload_and_test_parts_listing "$test_file" "$policy_file"
  assert_success "error creating upload and testing parts listing"
}
