#!/usr/bin/env bats

source ./tests/test_user_common.sh

@test "test_admin_user_s3cmd" {
  test_admin_user "s3cmd"
}

@test "test_create_user_already_exists_s3cmd" {
  test_create_user_already_exists "s3cmd"
}

@test "test_user_user_s3cmd" {
  test_user_user "s3cmd"
}

@test "test_userplus_operation_s3cmd" {
  test_userplus_operation "s3cmd"
}
