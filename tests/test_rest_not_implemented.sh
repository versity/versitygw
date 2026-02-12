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

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/not_implemented/not_implemented_rest.sh
source ./tests/setup.sh

@test "REST - PutBucketAnalyticsConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "analytics=" "PUT"
  assert_success
}

@test "REST - GetBucketAnalyticsConfiguration - with template" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1821"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_file_name
  assert_success
  file_name=$output

  run send_rest_go_command_write_response_to_file "$TEST_FILE_FOLDER/$file_name" "-bucketName" "$bucket_name" "-query" "analytics="
  assert_success

  run bash -c "go run ./tests/checker/main.go -dataFile $TEST_FILE_FOLDER/$file_name -batsTestFileName $BATS_TEST_FILENAME \
    -batsTestName $BATS_TEST_NAME -serverName $SERVER_NAME -matrixFile $TEMPLATE_MATRIX_FILE"
  assert_success
}

@test "REST - NotImplemented - correct Content-Type header" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1821"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_check_header_key_and_value "501" "Content-Type" "application/xml" "-bucketName" "$bucket_name" \
    "-query" "analytics"
  assert_success
}

@test "REST - Get/ListBucketAnalyticsConfiguration(s)" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "analytics=" "GET"
  assert_success
}

@test "REST - DeleteBucketAnalyticsConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "analytics=" "DELETE"
  assert_success
}

@test "REST - GetBucketEncryption" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "encryption=" "GET"
  assert_success
}

@test "REST - PutBucketEncryption" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "encryption=" "PUT"
  assert_success
}

@test "REST - DeleteBucketEncryption" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "encryption=" "DELETE"
  assert_success
}

@test "REST - ListBucketIntelligentTieringConfigurations" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "intelligent-tiering=" "GET"
  assert_success
}

@test "REST - PutBucketIntelligentTieringConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "intelligent-tiering=" "PUT"
  assert_success
}

@test "REST - DeleteBucketIntelligentTieringConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "intelligent-tiering=" "DELETE"
  assert_success
}

@test "REST - ListBucketInventoryConfigurations" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "inventory=" "GET"
  assert_success
}

@test "REST - PutBucketInventoryConfigurations" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "inventory=" "PUT"
  assert_success
}

@test "REST - DeleteBucketInventoryConfigurations" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "inventory=" "DELETE"
  assert_success
}

@test "REST - GetBucketLifecycleConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "lifecycle=" "GET"
  assert_success
}

@test "REST - PutBucketLifecycleConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "lifecycle=" "PUT"
  assert_success
}

@test "REST - DeleteBucketLifecycleConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "lifecycle=" "DELETE"
  assert_success
}

@test "REST - GetBucketLogging" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "logging=" "GET"
  assert_success
}

@test "REST - PutBucketLogging" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "logging=" "PUT"
  assert_success
}

@test "REST - ListBucketMetricsConfigurations" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "metrics=" "GET"
  assert_success
}

@test "REST - PutBucketMetricsConfigurations" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "metrics=" "PUT"
  assert_success
}

@test "REST - DeleteBucketMetricsConfigurations" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "metrics=" "DELETE"
  assert_success
}

@test "REST - GetBucketReplication" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "replication=" "GET"
  assert_success
}

@test "REST - PutBucketReplication" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "replication=" "PUT"
  assert_success
}

@test "REST - DeleteBucketReplication" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "replication=" "DELETE"
  assert_success
}

@test "REST - GetBucketWebsite" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "website=" "GET"
  assert_success
}

@test "REST - PutBucketWebsite" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "website=" "PUT"
  assert_success
}

@test "REST - DeleteBucketWebsite" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "website=" "DELETE"
  assert_success
}

@test "REST - GetPublicAccessBlock" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "publicAccessBlock=" "GET"
  assert_success
}

@test "REST - PutPublicAccessBlock" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "publicAccessBlock=" "PUT"
  assert_success
}

@test "REST - DeletePublicAccessBlock" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "publicAccessBlock=" "DELETE"
  assert_success
}

@test "REST - GetBucketAccelerateConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "accelerate=" "GET"
  assert_success
}

@test "REST - PutBucketAccelerateConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "accelerate=" "PUT"
  assert_success
}

@test "REST - GetBucketNotificationConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "notification=" "GET"
  assert_success
}

@test "REST - PutBucketNotificationConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "notification=" "PUT"
  assert_success
}

@test "REST - GetBucketRequestPayment" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "requestPayment=" "GET"
  assert_success
}

@test "REST - PutBucketRequestPayment" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "requestPayment=" "PUT"
  assert_success
}

@test "REST - GetObjectAcl" {
  run get_file_name
  assert_success
  file_name=$output

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$file_name"
  assert_success

  run send_not_implemented_expect_failure "-bucketName" "$bucket_name" "-query" "acl=" "-method" "GET" "-objectKey" "$file_name"
  assert_success
}

@test "REST - PutObjectAcl" {
  run get_file_name
  assert_success
  file_name=$output

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$file_name"
  assert_success

  run send_not_implemented_expect_failure "-bucketName" "$bucket_name" "-query" "acl=" "-method" "PUT" "-objectKey" "$file_name"
  assert_success
}

@test "REST - RestoreObject" {
  skip "https://github.com/versity/versitygw/issues/1805"

  run get_file_name
  assert_success
  file_name=$output

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_add_file "$bucket_name" "$file_name"
  assert_success

  run send_not_implemented_expect_failure "-bucketName" "$bucket_name" "-query" "restore=" "-method" "POST" "-objectKey" "$file_name"
  assert_success
}
