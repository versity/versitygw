#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util_users.sh
source ./tests/util.sh
source ./tests/util_bucket_create.sh

@test "test_admin_user" {
  admin_username="ABCDEF"
  user_username="GHIJKL"
  admin_password="123456"
  user_password="789012"

  user_exists "$admin_username" || local admin_exists_result=$?
  if [[ $admin_exists_result -eq 0 ]]; then
    delete_user "$admin_username" || local delete_admin_result=$?
    [[ $delete_admin_result -eq 0 ]] || fail "failed to delete admin user"
  fi
  create_user "$admin_username" "$admin_password" "admin" || create_admin_result=$?
  [[ $create_admin_result -eq 0 ]] || fail "failed to create admin user"

  user_exists "$user_username" || local user_exists_result=$?
  if [[ $user_exists_result -eq 0 ]]; then
    delete_user "$user_username" || local delete_user_result=$?
    [[ $delete_user_result -eq 0 ]] || fail "failed to delete user user"
  fi
  create_user_with_user "$admin_username" "$admin_password" "$user_username" "$user_password" "user"

  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  delete_bucket "aws" "versity-gwtest-admin-bucket" || local delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "error deleting bucket if it exists"
  create_bucket_with_user "aws" "versity-gwtest-admin-bucket" "$admin_username" "$admin_password" || create_result_two=$?
  [[ $create_result_two -eq 0 ]] || fail "error creating bucket with user"

  bucket_one_found=false
  bucket_two_found=false
  list_buckets_with_user "aws" "$admin_username" "$admin_password"
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$BUCKET_ONE_NAME" ]; then
      bucket_one_found=true
    elif [ "$bucket" == "versity-gwtest-admin-bucket" ]; then
      bucket_two_found=true
    fi
    if [ $bucket_one_found == true ] && [ $bucket_two_found == true ]; then
      break
    fi
  done
  if [ $bucket_one_found == false ] || [ $bucket_two_found == false ]; then
    fail "not all expected buckets listed"
  fi
  change_bucket_owner "$admin_username" "$admin_password" "versity-gwtest-admin-bucket" "$user_username" || local change_result=$?
  [[ $change_result -eq 0 ]] || fail "error changing bucket owner"

  delete_bucket "aws" "versity-gwtest-admin-bucket"
  delete_user "$user_username"
  delete_user "$admin_username"
}

@test "test_create_user_already_exists" {
  username="ABCDEG"
  password="123456"

  user_exists "$username" || local exists_result=$?
  if [[ $exists_result -eq 0 ]]; then
    delete_user "$username" || local delete_result=$?
    [[ $delete_result -eq 0 ]] || fail "failed to delete user '$username'"
  fi

  create_user "$username" "123456" "admin" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "error creating user"
  create_user "$username" "123456" "admin" || local create_result=$?
  [[ $create_result -eq 1 ]] || fail "'user already exists' error not returned"

  delete_bucket "aws" "versity-gwtest-admin-bucket"
  delete_user "$username"
}

@test "test_user_user" {
  username="ABCDEG"
  password="123456"

  user_exists "$username" || local exists_result=$?
  if [[ $exists_result -eq 0 ]]; then
    delete_user "$username" || local delete_result=$?
    [[ $delete_result -eq 0 ]] || fail "failed to delete user '$username'"
  fi
  delete_bucket "aws" "versity-gwtest-user-bucket"

  create_user "$username" "123456" "user" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "error creating user"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  create_bucket_with_user "aws" "versity-gwtest-user-bucket" "$username" "$password" || create_result_two=$?
  [[ $create_result_two -eq 1 ]] || fail "creating bucket with 'user' account failed to return error"
  [[ $error == *"Access Denied"* ]] || fail "error message '$error' doesn't contain 'Access Denied'"

  create_bucket "aws" "versity-gwtest-user-bucket" || create_result_three=$?
  [[ $create_result_three -eq 0 ]] || fail "creating bucket account returned error"

  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "versity-gwtest-user-bucket" "$username" || local change_result=$?
  [[ $change_result -eq 0 ]] || fail "error changing bucket owner"
  change_bucket_owner "$username" "$password" "versity-gwtest-user-bucket" "admin" || local change_result_two=$?
  [[ $change_result_two -eq 1 ]] || fail "user shouldn't be able to change bucket owner"

  list_buckets_with_user "aws" "$username" "$password"
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

  delete_bucket "aws" "versity-gwtest-user-bucket"
  delete_user "$username"
}

@test "test_userplus_operation" {
  username="ABCDEG"
  password="123456"

  user_exists "$username" || local exists_result=$?
  if [[ $exists_result -eq 0 ]]; then
    delete_user "$username" || local delete_result=$?
    [[ $delete_result -eq 0 ]] || fail "failed to delete user '$username'"
  fi
  delete_bucket "aws" "versity-gwtest-userplus-bucket"

  create_user "$username" "123456" "userplus" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "error creating user"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  create_bucket_with_user "aws" "versity-gwtest-userplus-bucket" "$username" "$password" || create_result_two=$?
  [[ $create_result_two -eq 0 ]] || fail "error creating bucket"

  list_buckets_with_user "aws" "$username" "$password"
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

  change_bucket_owner "$username" "$password" "versity-gwtest-userplus-bucket" "admin" || local change_result_two=$?
  [[ $change_result_two -eq 1 ]] || fail "userplus shouldn't be able to change bucket owner"

  delete_bucket "aws" "versity-gwtest-admin-bucket"
  delete_user "$username" || delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "error deleting user"
}
