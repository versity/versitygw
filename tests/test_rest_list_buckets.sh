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

load ./bats-support/load
load ./bats-assert/load

source ./tests/commands/list_buckets.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/list_buckets/list_buckets_rest.sh
source ./tests/drivers/user.sh
source ./tests/logger.sh
source ./tests/setup.sh

export RUN_USERS=true

@test "REST - empty message" {
  test_file="test_file"
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1249"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_file_v2 "$bucket_name" "$test_file"
  assert_success

  echo -en "\r\n" > "$TEST_FILE_FOLDER/empty.txt"
  run send_via_openssl_with_timeout "$TEST_FILE_FOLDER/empty.txt"
  assert_success
}

@test "REST - deformed message" {
  test_file="test_file"
  echo -en "abcdefg\r\n\r\n" > "$TEST_FILE_FOLDER/deformed.txt"
  run send_via_openssl_check_code_error_contains "$TEST_FILE_FOLDER/deformed.txt" 400 "BadRequest" "An error occurred when parsing the HTTP request."
  assert_success
}

@test "REST - invalid authorization scheme" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1705"
  fi
  run list_buckets_check_authorization_scheme_error
  assert_success
}

@test "REST - very invalid credential string" {
  run send_rest_go_command_expect_error "400" "AuthorizationHeaderMalformed" "the Credential is mal-formed" "-incorrectCredential" "Credentials"
  assert_success
}

@test "REST - nonexistent key ID" {
  run send_rest_go_command_expect_error "403" "InvalidAccessKeyId" "does not exist" "-awsAccessKeyId" "dummy"
  assert_success
}

@test "REST - invalid year/month/day" {
  run send_rest_go_command_expect_error "400" "AuthorizationHeaderMalformed" "incorrect date format" "-invalidYearMonthDay"
  assert_success
}

@test "REST - incorrect year/month/day" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1514"
  fi
  run list_buckets_check_request_time_too_skewed_error
  assert_success
}

@test "REST - invalid region" {
  run send_rest_go_command_expect_error "400" "AuthorizationHeaderMalformed" "us-eest-1" "-awsRegion" "us-eest-1"
  assert_success
}

@test "REST - invalid service name" {
  run send_rest_go_command_expect_error "400" "AuthorizationHeaderMalformed" "incorrect service" "-serviceName" "s2"
  assert_success
}

@test "REST - incorrect signature" {
  run send_rest_go_command_expect_error "403" "SignatureDoesNotMatch" "does not match" "-incorrectSignature"
  assert_success
}

@test "REST - missing host parameter" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1530"
  fi
  run send_openssl_go_command "400" "-missingHostParam"
  assert_success
}

@test "test_rest_list_buckets" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket "$bucket_name"
  assert_success

  run list_check_buckets_rest "$bucket_name"
  assert_success
}

@test "REST - list buckets - continuation token isn't bucket name" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1399"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_bucket_name "$BUCKET_TWO_NAME"
  assert_success
  bucket_two_name="$output"

  run setup_buckets_v2 "$bucket_name" "$bucket_two_name"
  assert_success

  run check_continuation_token
  assert_success
}

@test "REST - list buckets - success (multiple pages)" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_bucket_name "$BUCKET_TWO_NAME"
  assert_success
  bucket_two_name="$output"

  run setup_buckets_v2 "$bucket_name" "$bucket_two_name"
  assert_success

  run check_for_buckets_with_multiple_pages "$bucket_name" "$bucket_two_name"
  assert_success
}

@test "REST - list buckets w/prefix" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run get_bucket_name "$BUCKET_TWO_NAME"
  assert_success
  bucket_two_name="$output"

  run setup_buckets_v2 "$bucket_name" "$bucket_two_name"
  assert_success

  run list_check_buckets_rest "$bucket_name" "$bucket_two_name"
  assert_success

  run list_check_buckets_rest_with_prefix "$bucket_name"
  assert_success

  run list_check_buckets_rest_with_prefix "$bucket_two_name"
  assert_success
}

@test "REST - ListBuckets - correct buckets show up" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip "skip versitygw-specific users tests"
  fi
  if [ "$DIRECT" == "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1704"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_user "$bucket_name" "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success
  username=${lines[${#lines[@]}-2]}
  password=${lines[${#lines[@]}-1]}

  run get_bucket_name "$BUCKET_TWO_NAME"
  assert_success
  bucket_two_name="$output"

  run setup_bucket "$bucket_two_name"
  assert_success

  run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$bucket_two_name" "$username"
  assert_success

  log 5 "username: $username, password: $password"
  run list_check_buckets_user "$username" "$password" "$bucket_two_name"
  assert_success
}

@test "REST - ListBuckets - invalid POST route" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1810"
  fi
  run get_file_name
  assert_success
  file_name=$output

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_expect_error_with_specific_arg_names_values "405" "MethodNotAllowed" "is not allowed" 4 "Method" "POST" "ResourceType" "SERVICE" "-method" "POST"
  assert_success
}

@test "REST - ListBuckets - invalid method" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1846"
  fi
  run send_rest_go_command_expect_error "400" "BadRequest" "An error occurred when parsing the HTTP request" "-method" "GETS"
  assert_success
}

@test "REST - ListBuckets - error Content-Type is application/xml" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1852"
  fi
  run send_rest_go_command_check_header_key_and_value "400" "Content-Type" "application/xml" "-method" "GETS"
  assert_success
}