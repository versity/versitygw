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

source ./tests/drivers/not_implemented/not_implemented_rest.sh
source ./tests/setup.sh

@test "REST - PutBucketAnalyticsConfiguration" {
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "analytics=" "PUT"
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

@test "REST - GetBucketPolicyStatus" {
  skip "https://github.com/versity/versitygw/issues/1454"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "policyStatus=" "GET"
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
