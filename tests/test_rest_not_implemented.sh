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
  skip "https://github.com/versity/versitygw/issues/1433"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "analytics=" "PUT"
  assert_success
}

@test "REST - Get/ListBucketAnalyticsConfiguration(s)" {
  skip "https://github.com/versity/versitygw/issues/1437"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "analytics=" "GET"
  assert_success
}

@test "REST - DeleteBucketAnalyticsConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1438"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "analytics=" "DELETE"
  assert_success
}

@test "REST - GetBucketEncryption" {
  skip "https://github.com/versity/versitygw/issues/1439"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "encryption=" "GET"
  assert_success
}

@test "REST - PutBucketEncryption" {
  skip "https://github.com/versity/versitygw/issues/1439"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "encryption=" "PUT"
  assert_success
}

@test "REST - DeleteBucketEncryption" {
  skip "https://github.com/versity/versitygw/issues/1439"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "encryption=" "DELETE"
  assert_success
}

@test "REST - ListBucketIntelligentTieringConfigurations" {
  skip "https://github.com/versity/versitygw/issues/1440"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "intelligent-tiering=" "GET"
  assert_success
}

@test "REST - PutBucketIntelligentTieringConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1440"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "intelligent-tiering=" "PUT"
  assert_success
}

@test "REST - DeleteBucketIntelligentTieringConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1440"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "intelligent-tiering=" "DELETE"
  assert_success
}

@test "REST - ListBucketInventoryConfigurations" {
  skip "https://github.com/versity/versitygw/issues/1441"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "inventory=" "GET"
  assert_success
}

@test "REST - PutBucketInventoryConfigurations" {
  skip "https://github.com/versity/versitygw/issues/1441"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "inventory=" "PUT"
  assert_success
}

@test "REST - DeleteBucketInventoryConfigurations" {
  skip "https://github.com/versity/versitygw/issues/1441"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "inventory=" "DELETE"
  assert_success
}

@test "REST - GetBucketLifecycleConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1443"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "lifecycle=" "GET"
  assert_success
}

@test "REST - PutBucketLifecycleConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1443"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "lifecycle=" "PUT"
  assert_success
}

@test "REST - DeleteBucketLifecycleConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1443"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "lifecycle=" "DELETE"
  assert_success
}

@test "REST - GetBucketLogging" {
  skip "https://github.com/versity/versitygw/issues/1444"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "logging=" "GET"
  assert_success
}

@test "REST - PutBucketLogging" {
  skip "https://github.com/versity/versitygw/issues/1444"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "logging=" "PUT"
  assert_success
}

@test "REST - ListBucketMetricsConfigurations" {
  skip "https://github.com/versity/versitygw/issues/1445"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "metrics=" "GET"
  assert_success
}

@test "REST - PutBucketMetricsConfigurations" {
  skip "https://github.com/versity/versitygw/issues/1445"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "metrics=" "PUT"
  assert_success
}

@test "REST - DeleteBucketMetricsConfigurations" {
  skip "https://github.com/versity/versitygw/issues/1445"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "metrics=" "DELETE"
  assert_success
}

@test "REST - GetBucketReplication" {
  skip "https://github.com/versity/versitygw/issues/1449"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "replication=" "GET"
  assert_success
}

@test "REST - PutBucketReplication" {
  skip "https://github.com/versity/versitygw/issues/1449"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "replication=" "PUT"
  assert_success
}

@test "REST - DeleteBucketReplication" {
  skip "https://github.com/versity/versitygw/issues/1449"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "replication=" "DELETE"
  assert_success
}

@test "REST - GetBucketWebsite" {
  skip "https://github.com/versity/versitygw/issues/1450"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "website=" "GET"
  assert_success
}

@test "REST - PutBucketWebsite" {
  skip "https://github.com/versity/versitygw/issues/1450"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "website=" "PUT"
  assert_success
}

@test "REST - DeleteBucketWebsite" {
  skip "https://github.com/versity/versitygw/issues/1450"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "website=" "DELETE"
  assert_success
}

@test "REST - GetPublicAccessBlock" {
  skip "https://github.com/versity/versitygw/issues/1451"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "publicAccessBlock=" "GET"
  assert_success
}

@test "REST - PutPublicAccessBlock" {
  skip "https://github.com/versity/versitygw/issues/1451"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "publicAccessBlock=" "PUT"
  assert_success
}

@test "REST - DeletePublicAccessBlock" {
  skip "https://github.com/versity/versitygw/issues/1451"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "publicAccessBlock=" "DELETE"
  assert_success
}

@test "REST - GetBucketAccelerateConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1452"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "accelerate=" "GET"
  assert_success
}

@test "REST - PutBucketAccelerateConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1452"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "accelerate=" "PUT"
  assert_success
}

@test "REST - GetBucketNotificationConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1453"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "notification=" "GET"
  assert_success
}

@test "REST - PutBucketNotificationConfiguration" {
  skip "https://github.com/versity/versitygw/issues/1453"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "notification=" "PUT"
  assert_success
}

@test "REST - GetBucketPolicyStatus" {
  skip "https://github.com/versity/versitygw/issues/1454"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "policyStatus=" "GET"
  assert_success
}

@test "REST - GetBucketRequestPayment" {
  skip "https://github.com/versity/versitygw/issues/1455"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "requestPayment=" "GET"
  assert_success
}

@test "REST - PutBucketRequestPayment" {
  skip "https://github.com/versity/versitygw/issues/1455"
  run test_not_implemented_expect_failure "$BUCKET_ONE_NAME" "requestPayment=" "PUT"
  assert_success
}
