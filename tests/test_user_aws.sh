#!/usr/bin/env bats

source ./tests/test_user_common.sh

@test "test_admin_user_aws" {
  test_admin_user "aws"
}

@test "test_create_user_already_exists_aws" {
  test_create_user_already_exists "aws"
}

@test "test_user_user_aws" {
  test_user_user "aws"
}

@test "test_userplus_operation_aws" {
  test_userplus_operation "aws"
}
