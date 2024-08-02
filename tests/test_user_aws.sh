#!/usr/bin/env bats

source ./tests/test_user_common.sh
source ./tests/util_users.sh
source ./tests/commands/get_object.sh
source ./tests/commands/put_object.sh

export RUN_USERS=true

@test "test_admin_user_aws" {
  test_admin_user "aws"
}

@test "test_create_user_already_exists_aws" {
  test_create_user_already_exists "aws"
}

@test "test_delete_user_no_access_key" {
  if delete_user ""; then
    fail "delete user with empty access key succeeded"
  fi
}

@test "test_user_user_aws" {
  test_user_user "aws"
}

@test "test_userplus_operation_aws" {
  test_userplus_operation "aws"
}

@test "test_user_get_object" {
  username="$USERNAME_ONE"
  password="$USERNAME_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "user" || fail "error creating user if nonexistent"
  create_test_files "$test_file" || fail "error creating test files"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite not being bucket owner"
  fi
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "failed to add object to bucket"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error getting object"
}

@test "test_userplus_get_object" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "admin" || fail "error creating user if nonexistent"
  create_test_files "$test_file" || fail "error creating test files"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite not being bucket owner"
  fi
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "failed to add object to bucket"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error getting object"
}

@test "test_user_delete_object" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "user" || fail "error creating user if nonexistent"
  create_test_files "$test_file" || fail "error creating test files"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite not being bucket owner"
  fi
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "failed to add object to bucket"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "error deleting object"
}

@test "test_admin_put_get_object" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "admin" || fail "error creating user if nonexistent"
  create_test_file_with_size "$test_file" 10 || fail "error creating test file"

  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  put_object_with_user "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "failed to add object to bucket"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error getting object"
  compare_files "$test_file_folder/$test_file" "$test_file_folder/$test_file-copy" || fail "files don't match"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "error deleting object"
  if get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy"; then
    fail "file not successfully deleted"
  fi
  # shellcheck disable=SC2154
  [[ "$get_object_error" == *"NoSuchKey"* ]] || fail "unexpected error message: $get_object_error"
  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file" "$test_file-copy"
}

@test "test_user_create_multipart_upload" {
  username="$USERNAME_ONE"
  password="$PASSWORD_ONE"
  test_file="test_file"

  setup_user "$username" "$password" "user" || fail "error creating user if nonexistent"
  create_large_file "$test_file" || fail "error creating test file"
  setup_bucket "s3api" "$BUCKET_ONE_NAME"
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$username" || fail "error changing bucket ownership"
  create_multipart_upload_with_user "$BUCKET_ONE_NAME" "dummy" "$username" "$password" || fail "unable to create multipart upload"
}
