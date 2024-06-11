#!/usr/bin/env bats

source ./tests/test_user_common.sh

export RUN_S3CMD=true
export RUN_USERS=true

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
