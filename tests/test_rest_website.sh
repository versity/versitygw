#!/usr/bin/env bats

# Copyright 2026 Versity Software
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

source ./tests/commands/put_public_access_block.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_bucket_website/get_bucket_website_rest.sh
source ./tests/drivers/put_bucket_website/put_bucket_website_rest.sh
source ./tests/drivers/cloudfront.sh
source ./tests/drivers/string.sh
source ./tests/setup_env_and_versitygw.sh

setup() {
  if ! setup_env; then
    log 1 "error setting up env"
    return 1
  fi
}

teardown() {
  teardown_common
}

@test "PutBucketWebsite - empty payload" {
  local bucket_name

  run setup_versitygw
  assert_success
  process_id="$output"
  export VERSITYGW_PID_1="$process_id"

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run send_rest_go_command_expect_error "400" "MissingRequestBodyError" "Request Body is empty" "-bucketName" "$bucket_name" "-method" "PUT" "-query" "website"
  assert_success
}

@test "PutBucketWebsite - XML message with empty WebsiteConfiguration struct" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2260"
  fi
  local bucket_name

  run setup_versitygw
  assert_success
  process_id="$output"
  export VERSITYGW_PID_1="$process_id"

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run send_rest_go_command_expect_error "400" "InvalidArgument" "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty" \
    "-commandType" "putBucketWebsiteConfiguration" "-bucketName" "$bucket_name" "-websiteConfiguration" "{}"
  assert_success
}

@test "PutBucketWebsite - HTTP call with HTTPS enabled does not return empty response" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2261"
  fi
  distribution_created=false

  run setup_versitygw
  assert_success
  process_id="$output"
  export VERSITYGW_PID_1="$process_id"

  local bucket_name policy_file distribution_domain http_domain

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_website_with_random_string "$bucket_name"
  assert_success
  random_string="$output"

  if [ "$DIRECT" == "true" ]; then
    run put_public_access_block "$bucket_name" "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
    assert_success
  fi

  run setup_policy_with_single_statement_v2 "2012-10-17" "Allow" "*" "s3:GetObject" "arn:aws:s3:::$bucket_name/*"
  assert_success
  policy_file="$output"

  run put_bucket_policy "rest" "$bucket_name" "$TEST_FILE_FOLDER"/"$policy_file"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run create_cloudfront_distribution "$bucket_name" "index.html" "${bucket_name}.s3-website.us-east-1.amazonaws.com"
    assert_success
    # shellcheck disable=SC2034
    distribution_created=true
    distribution_domain="$output"
    http_domain="${distribution_domain/https:\/\//http:\/\/}"
  else
    http_domain="${AWS_ENDPOINT_URL/https:\/\//http:\/\/}"
  fi

  run curl -ks "${http_domain}"
  assert_success
  assert_output -p "301 Moved Permanently"
}

@test "PutBucketWebsite - IndexDocument suffix" {
  local bucket_name policy_file random_string

  run setup_versitygw
  assert_success
  process_id="$output"
  export VERSITYGW_PID_1="$process_id"

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_website_with_random_string_and_add_permissions "$bucket_name"
  assert_success
  read -r random_string <<< "$output"

  run curl -ks "https://${bucket_name}.${WEBSITE_DOMAIN}${WEBSITE}"
  assert_success
  assert_output "$random_string"
}

@test "REST - GetBucketWebsite - IndexDocument Suffix, DeleteBucketWebsite" {
  local bucket_name test_file random_string

  run setup_versitygw
  assert_success
  process_id="$output"
  export VERSITYGW_PID_1="$process_id"

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_website_with_random_string "$bucket_name"
  assert_success
  read -r test_file random_string <<< "$output"

  run check_index_document_suffix "$bucket_name" "$test_file"
  assert_success

  run send_rest_go_command "204" "-method" "DELETE" "-query" "website" "-bucketName" "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error_with_specific_arg_name_value "404" "NoSuchWebsiteConfiguration" \
    "does not have a website configuration" "BucketName" "$bucket_name" "-query" "website" "-bucketName" "$bucket_name"
  assert_success
}

@test "REST - GetBucketWebsite - no HTTPS" {
  run setup_versitygw "--website-no-tls"
  assert_success
  process_id="$output"
  log 5 "process ID: $process_id"
  export VERSITYGW_PID_1="$process_id"

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_website_with_random_string_and_add_permissions "$bucket_name"
  assert_success
  read -r random_string <<< "$output"

  run curl -ks "http://${bucket_name}.${WEBSITE_DOMAIN}${WEBSITE}"
  assert_success
  assert_output "$random_string"
}
