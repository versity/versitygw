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

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/get_bucket_cors/get_bucket_cors_rest.sh
source ./tests/setup.sh

@test "REST - GetCors - correct content-type, and returns bucket name" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1842"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_bucket_cors_check_404_header_and_bucket_name "$bucket_name"
  assert_success
}

@test "REST - PutBucketCors and GetBucketCors - valid configuration" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_bucket_cors_check_valid_data "$bucket_name"
  assert_success
}

@test "REST - CORS - empty CORS rule" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1863"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "MalformedXML" "did not validate" "-bucketName" "$bucket_name" "-query" "cors" "-method" "PUT" \
    "-payload" "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><CORSRule></CORSRule></CORSConfiguration>" "-contentMD5"
  assert_success
}

@test "REST - CORS - missing allowed origin" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1863"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "MalformedXML" "did not validate" "-bucketName" "$bucket_name" "-query" "cors" "-method" "PUT" \
    "-payload" "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><CORSRule><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>" "-contentMD5"
  assert_success
}

@test "REST - CORS - missing allowed method" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1863"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "MalformedXML" "did not validate" "-bucketName" "$bucket_name" "-query" "cors" "-method" "PUT" \
    "-payload" "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><CORSRule><AllowedOrigin>example.com</AllowedOrigin></CORSRule></CORSConfiguration>" "-contentMD5"
  assert_success
}

@test "REST - CORS - empty allowed method" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1863"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "unsupported HTTP method in CORS config" "-bucketName" "$bucket_name" "-query" "cors" "-method" "PUT" \
    "-payload" "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><CORSRule><AllowedOrigin>example.com</AllowedOrigin><AllowedMethod></AllowedMethod></CORSRule></CORSConfiguration>" "-contentMD5"
  assert_success
}

@test "REST - CORS - invalid origin" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1870"
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run send_rest_go_command_expect_error "400" "InvalidRequest" "can not have more than one wildcard" "-bucketName" "$bucket_name" "-query" "cors" "-method" "PUT" \
    "-payload" "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><CORSRule><AllowedOrigin>*example*.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>" "-contentMD5"
  assert_success
}

@test "REST - CORS - delete" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run get_bucket_cors_check_valid_data "$bucket_name"
  assert_success

  run send_rest_go_command "204" "-bucketName" "$bucket_name" "-query" "cors" "-method" "DELETE"
  assert_success

  run send_rest_go_command_expect_error "404" "NoSuchCORSConfiguration" "does not exist" "-query" "cors" "-bucketName" "$bucket_name"
  assert_success
}
