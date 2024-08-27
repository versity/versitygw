#!/usr/bin/env bats

source ./tests/util_multipart.sh
source ./tests/util_tags.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/put_bucket_tagging.sh

test_s3api_policy_invalid_action() {
  policy_file="policy_file"

  create_test_files "$policy_file" || fail "error creating policy file"

  effect="Allow"
  principal="*"
  action="s3:GetObjectt"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"

  # shellcheck disable=SC2154
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"

  check_for_empty_policy "s3api" "$BUCKET_ONE_NAME" || fail "policy not empty"

  if put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file"; then
    fail "put succeeded despite malformed policy"
  fi
  # shellcheck disable=SC2154
  [[ "$put_bucket_policy_error" == *"MalformedPolicy"*"invalid action"* ]] || fail "invalid policy error: $put_bucket_policy_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file"
}

test_s3api_policy_get_object_with_user() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE
  test_file="test_file"

  log 5 "username: $USERNAME_ONE, password: $PASSWORD_ONE"
  create_test_files "$test_file" "$policy_file" || fail "error creating policy file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"

  setup_policy_with_single_statement "$test_file_folder/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "error copying object"

  if ! check_for_empty_policy "s3api" "$BUCKET_ONE_NAME"; then
    delete_bucket_policy "s3api" "$BUCKET_ONE_NAME" || fail "error deleting policy"
    check_for_empty_policy "s3api" "$BUCKET_ONE_NAME" || fail "policy not empty after deletion"
  fi

  setup_user "$username" "$password" "user" || fail "error creating user"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password"; then
    fail "get object with user succeeded despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error getting object after permissions"
  compare_files "$test_file_folder/$test_file" "$test_file_folder/$test_file-copy" || fail "files not equal"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

test_s3api_policy_get_object_specific_file() {
  policy_file="policy_file"
  test_file="test_file"
  test_file_two="test_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" "$test_file" "$test_file_two" || fail "error creating policy file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file"
  echo "$BATS_TEST_NAME-2" >> "$test_file_folder/$test_file_two"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/test_file"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "error copying object"
  put_object "s3api" "$test_file_folder/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object"

  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error getting object after permissions"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$test_file_folder/$test_file_two-copy" "$username" "$password"; then
    fail "get object with user succeeded despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

test_s3api_policy_get_object_file_wildcard() {
  policy_file="policy_file_one"
  policy_file_two="policy_file_two"
  policy_file_three="policy_fil"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" "$policy_file_two" "$policy_file_three" || fail "error creating policy file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$policy_file"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/policy_file*"

  setup_user "$username" "$password" "user" || fail "error creating user account"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$policy_file" "$BUCKET_ONE_NAME" "$policy_file" || fail "error copying object one"
  put_object "s3api" "$test_file_folder/$policy_file_two" "$BUCKET_ONE_NAME" "$policy_file_two" || fail "error copying object two"
  put_object "s3api" "$test_file_folder/$policy_file_three" "$BUCKET_ONE_NAME" "$policy_file_three" || fail "error copying object three"

  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$policy_file" "$test_file_folder/$policy_file" "$username" "$password" || fail "error getting object one after permissions"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$policy_file_two" "$test_file_folder/$policy_file_two" "$username" "$password" || fail "error getting object two after permissions"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$policy_file_three" "$test_file_folder/$policy_file_three" "$username" "$password"; then
    fail "get object three with user succeeded despite lack of permissions"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

test_s3api_policy_get_object_folder_wildcard() {
  policy_file="policy_file"
  test_folder="test_folder"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_folder "$test_folder" || fail "error creating test folder"
  create_test_files "$test_folder/$test_file" "$policy_file" || fail "error creating policy file, test file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_folder/$test_file"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" || fail "error copying object to bucket"

  download_and_compare_file_with_user "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error downloading and comparing file"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_folder/$test_file" "$policy_file"
}

test_s3api_policy_allow_deny() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" "$test_file" || fail "error creating policy file"
  setup_user "$username" "$password" "user" || fail "error creating user"
  setup_bucket "s3api" "$BUCKET_ONE_NAME"

  setup_policy_with_double_statement "$test_file_folder/$policy_file" "dummy" \
    "Deny" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file" \
    "Allow" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "error copying object to bucket"

  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite deny statement"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file" "$test_file-copy" "$policy_file"
}

test_s3api_policy_deny() {
  policy_file="policy_file"
  test_file_one="test_file_one"
  test_file_two="test_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$test_file_one" "$test_file_two" "$policy_file" || fail "error creating policy file, test file"
  setup_user "$username" "$password" "user" || fail "error creating user"
  setup_bucket "s3api" "$BUCKET_ONE_NAME"

  setup_policy_with_double_statement "$test_file_folder/$policy_file" "dummy" \
    "Deny" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two" \
    "Allow" "$username" "s3:GetObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*"

  log 5 "Policy: $(cat "$test_file_folder/$policy_file")"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  put_object "s3api" "$test_file_folder/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one" || fail "error copying object one"
  put_object "s3api" "$test_file_folder/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object two"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_one" "$test_file_folder/$test_file_one-copy" "$username" "$password" || fail "error getting object"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$test_file_folder/$test_file_two-copy" "$username" "$password"; then
    fail "able to get object despite deny statement"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file_one" "$test_file_two" "$test_file_one-copy" "$test_file_two-copy" "$policy_file"
}

test_s3api_policy_put_wildcard() {
  policy_file="policy_file"
  test_folder="test_folder"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_folder "$test_folder" || fail "error creating test folder"
  create_test_files "$test_folder/$test_file" "$policy_file" || fail "error creating policy file, test file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_folder/$test_file"

  effect="Allow"
  principal="$username"
  action="s3:PutObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  log 5 "Policy: $(cat "$test_file_folder/$policy_file")"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  if put_object_with_user "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"; then
    fail "able to put object despite not being allowed"
  fi
  # shellcheck disable=SC2154
  [[ "$put_object_error" == *"Access Denied"* ]] || fail "invalid put object error: $put_object_error"
  put_object_with_user "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$username" "$password" || fail "error putting file despite policy permissions"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_folder/$test_file-copy" "$username" "$password"; then
    fail "able to get object without permissions"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  download_and_compare_file "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_file_folder/$test_file-copy" || fail "files don't match"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_folder/$test_file" "$test_file-copy" "$policy_file"
}

test_s3api_policy_delete() {
  policy_file="policy_file"
  test_file_one="test_file_one"
  test_file_two="test_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$test_file_one" "$test_file_two" "$policy_file" || fail "error creating policy file, test files"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file_one"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file_two"

  effect="Allow"
  principal="$username"
  action="s3:DeleteObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  log 5 "Policy: $(cat "$test_file_folder/$policy_file")"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one" || fail "error copying object one"
  put_object "s3api" "$test_file_folder/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object two"
  if delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_one" "$username" "$password"; then
    fail "able to delete object despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$delete_object_error" == *"Access Denied"* ]] || fail "invalid delete object error: $delete_object_error"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$username" "$password" || fail "error deleting object despite permissions"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file_one" "$test_file_two" "$policy_file"
}

test_s3api_policy_get_bucket_policy() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:GetBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  if get_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "able to retrieve bucket policy despite lack of permissions"
  fi

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  get_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error getting bucket policy despite permissions"
  # shellcheck disable=SC2154
  echo "$bucket_policy" > "$test_file_folder/$policy_file-copy"
  log 5 "ORIG: $(cat "$test_file_folder/$policy_file")"
  log 5 "COPY: $(cat "$test_file_folder/$policy_file-copy")"
  compare_files "$test_file_folder/$policy_file" "$test_file_folder/$policy_file-copy" || fail "policies not equal"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$policy_file-copy"
}

test_s3api_policy_list_multipart_uploads() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" || fail "error creating policy file, test files"
  create_large_file "$test_file"

  effect="Allow"
  principal="$username"
  action="s3:ListBucketMultipartUploads"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"
  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  get_bucket_policy "s3api" "$BUCKET_ONE_NAME" || fail "error getting bucket policy"
  log 5 "BUCKET POLICY: $bucket_policy"
  get_bucket_acl "s3api" "$BUCKET_ONE_NAME" || fail "error getting bucket ACL"
  # shellcheck disable=SC2154
  log 5 "ACL: $acl"
  run setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource"
  assert_success "failed to set up policy"
  run create_multipart_upload "$BUCKET_ONE_NAME" "$test_file"
  assert_success "failed to create multipart upload"
  if list_multipart_uploads_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "able to list multipart uploads despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$list_multipart_uploads_error" == *"Access Denied"* ]] || fail "invalid list multipart uploads error: $list_multipart_uploads_error"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  list_multipart_uploads_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error listing multipart uploads"
  # shellcheck disable=SC2154
  log 5 "$uploads"
  upload_key=$(echo "$uploads" | grep -v "InsecureRequestWarning" | jq -r ".Uploads[0].Key" 2>&1) || fail "error parsing upload key from uploads message: $upload_key"
  [[ $upload_key == "$test_file" ]] || fail "upload key doesn't match file marked as being uploaded"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$test_file"
}

test_s3api_policy_put_bucket_policy() {
  policy_file="policy_file"
  policy_file_two="policy_file_two"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:PutBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  if put_bucket_policy_with_user "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" "$username" "$password"; then
    fail "able to retrieve bucket policy despite lack of permissions"
  fi

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  setup_policy_with_single_statement "$test_file_folder/$policy_file_two" "dummy" "$effect" "$principal" "s3:GetBucketPolicy" "$resource" || fail "failed to set up policy"
  put_bucket_policy_with_user "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file_two" "$username" "$password" || fail "error putting bucket policy despite permissions"
  get_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error getting bucket policy despite permissions"
  # shellcheck disable=SC2154
  echo "$bucket_policy" > "$test_file_folder/$policy_file-copy"
  log 5 "ORIG: $(cat "$test_file_folder/$policy_file_two")"
  log 5 "COPY: $(cat "$test_file_folder/$policy_file-copy")"
  compare_files "$test_file_folder/$policy_file_two" "$test_file_folder/$policy_file-copy" || fail "policies not equal"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$policy_file_two" "$policy_file-copy"
}

test_s3api_policy_delete_bucket_policy() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:DeleteBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  if delete_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "able to delete bucket policy with user $username without right permissions"
  fi
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  delete_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "unable to delete bucket policy"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file"
}

test_s3api_policy_get_bucket_acl() {
  policy_file="policy_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:GetBucketAcl"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  if get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "user able to get bucket ACLs despite permissions"
  fi
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error getting bucket ACL despite permissions"
}

test_s3api_policy_abort_multipart_upload() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE

  create_test_files "$policy_file" || fail "error creating policy file"
  create_large_file "$test_file"
  setup_bucket "s3api" "$BUCKET_ONE_NAME"
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

  setup_policy_with_double_statement "$test_file_folder/$policy_file" "2012-10-17" \
    "Allow" "$principal" "s3:PutObject" "arn:aws:s3:::$BUCKET_ONE_NAME/*" \
    "Deny" "$principal" "s3:AbortMultipartUpload" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting first policy"

  create_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "error creating multipart upload"
  # shellcheck disable=SC2154
  if abort_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password"; then
    fail "abort multipart upload succeeded despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$abort_multipart_upload_error" == *"AccessDenied"* ]] || fail "unexpected abort error:  $abort_multipart_upload_error"

  setup_policy_with_single_statement "$test_file_folder/$policy_file" "2012-10-17" "Allow" "$principal" "s3:AbortMultipartUpload" "arn:aws:s3:::$BUCKET_ONE_NAME/*"

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  abort_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password" || fail "error aborting multipart upload despite permissions"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$test_file"
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

  delete_test_files "$test_file" "$policy_file" "$TEST_FILE_FOLDER/copy_one" "$TEST_FILE_FOLDER/copy_two"
  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
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

  run setup_policy_with_single_statement "$test_file_folder/$policy_file" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success "error setting up policy"
  run put_bucket_tagging_with_user "$BUCKET_ONE_NAME" "$tag_key" "$tag_value" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_failure
  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file"
  assert_success "error putting policy"
  run put_bucket_tagging_with_user "$BUCKET_ONE_NAME" "$tag_key" "$tag_value" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success "unable to put bucket tagging despite user permissions"

  get_and_check_bucket_tags "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"

  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
}

test_s3api_policy_put_acl() {
  policy_file="policy_file"
  test_file="test_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  create_test_files "$policy_file" || fail "error creating policy file"
  create_large_file "$test_file"
  setup_bucket "s3api" "$BUCKET_ONE_NAME"

  put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred" || fail "error putting bucket ownership controls"

  setup_user "$username" "$password" "user" || fail "error setting up user $username"

  setup_policy_with_single_statement "$test_file_folder/$policy_file" "2012-10-17" "Allow" "$username" "s3:PutBucketAcl" "arn:aws:s3:::$BUCKET_ONE_NAME"
  if [[ $DIRECT == "true" ]]; then
    put_public_access_block_enable_public_acls "$BUCKET_ONE_NAME" || fail "error enabling public ACLs"
  fi

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_bucket_canned_acl_with_user "$BUCKET_ONE_NAME" "public-read" "$username" "$password" || fail "error putting canned acl"
  get_bucket_acl "s3api" "$BUCKET_ONE_NAME" || fail "error getting bucket acl"
  # shellcheck disable=SC2154
  log 5 "ACL: $acl"
  second_grant=$(echo "$acl" | jq -r ".Grants[1]" 2>&1) || fail "error getting second grant: $second_grant"
  second_grantee=$(echo "$second_grant" | jq -r ".Grantee" 2>&1) || fail "error getting second grantee: $second_grantee"
  permission=$(echo "$second_grant" | jq -r ".Permission" 2>&1) || fail "error getting permission: $permission"
  log 5 "second grantee: $second_grantee"
  [[ $permission == "READ" ]] || fail "incorrect permission: $permission"
  if [[ $DIRECT == "true" ]]; then
    uri=$(echo "$second_grantee" | jq -r ".URI" 2>&1) || fail "error getting uri: $uri"
    [[ $uri == "http://acs.amazonaws.com/groups/global/AllUsers" ]] || fail "unexpected URI: $uri"
  else
    id=$(echo "$second_grantee" | jq -r ".ID" 2>&1) || fail "error getting ID: $id"
    [[ $id == "all-users" ]] || fail "unexpected ID: $id"
  fi
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file"
}

test_s3api_policy_get_bucket_tagging() {
  policy_file="policy_file"
  test_file="test_file"
  tag_key="TestKey"
  tag_value="TestValue"

  run create_test_files "$policy_file"
  assert_success "error creating test files"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"

  run setup_user "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success "error creating user '$USERNAME_ONE'"

  run setup_policy_with_single_statement "$test_file_folder/$policy_file" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:GetBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success "error setting up policy"

  run put_bucket_tagging "s3api" "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success "unable to put bucket tagging"

  run get_bucket_tagging_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME"
  assert_failure

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file"
  assert_success "error putting policy"
  run get_and_check_bucket_tags_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$tag_key" "$tag_value"
  assert_success "get and check bucket tags failed"

  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file"
}

test_s3api_policy_list_upload_parts() {
  policy_file="policy_file"
  test_file="test_file"
  tag_key="TestKey"
  tag_value="TestValue"

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

  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$test_file"
}
