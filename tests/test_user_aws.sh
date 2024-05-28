#!/usr/bin/env bats

source ./tests/test_user_common.sh
source ./tests/util_users.sh

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
