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

source ./tests/commands/create_multipart_upload.sh
source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_versioning.sh
source ./tests/commands/get_object.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/get_object_retention.sh
source ./tests/commands/list_buckets.sh
source ./tests/commands/list_object_versions.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object.sh
source ./tests/commands/put_object_retention.sh
source ./tests/commands/put_object_tagging.sh
source ./tests/drivers/copy_object/copy_object_rest.sh
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_acl.sh
source ./tests/util/util_attributes.sh
source ./tests/util/util_chunked_upload.sh
source ./tests/util/util_delete_object.sh
source ./tests/util/util_head_object.sh
source ./tests/util/util_legal_hold.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_list_objects.sh
source ./tests/util/util_list_parts.sh
source ./tests/util/util_lock_config.sh
source ./tests/util/util_multipart_before_completion.sh
source ./tests/util/util_object.sh
source ./tests/util/util_ownership.sh
source ./tests/util/util_policy.sh
source ./tests/util/util_public_access_block.sh
source ./tests/util/util_rest.sh
source ./tests/util/util_setup.sh
source ./tests/util/util_tags.sh
source ./tests/util/util_time.sh
source ./tests/util/util_versioning.sh
source ./tests/util/util_xml.sh

export RUN_USERS=true
test_file="test_file"

@test "test_rest_list_objects" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run list_check_objects_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_rest_delete_object" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run delete_object "rest" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object "rest" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_failure
}

@test "test_rest_tagging" {
  test_key="TestKey"
  test_value="TestValue"

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_tagging "rest" "$BUCKET_ONE_NAME" "$test_file" "$test_key" "$test_value"
  assert_success

  run check_verify_object_tags "rest" "$BUCKET_ONE_NAME" "$test_file" "$test_key" "$test_value"
  assert_success

  run delete_object_tagging "rest" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run verify_no_object_tags "rest" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "test_rest_retention" {
  test_key="TestKey"
  test_value="TestValue"

  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success
  # in static bucket config, bucket will still exist
  if ! bucket_exists "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run create_test_files "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  if ! five_seconds_later=$(get_time_seconds_in_future 5 "%z"); then
    log 2 "error getting future time"
    return 1
  fi
  log 5 "later: $five_seconds_later"
  run put_object_retention_rest "$BUCKET_ONE_NAME" "$test_file" "GOVERNANCE" "$five_seconds_later"
  assert_success
}

@test "REST - legal hold, get without config" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_legal_hold_without_lock_enabled "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - get object attributes" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1001"
  fi
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  # shellcheck disable=SC2034
  file_size=$(stat -c %s "$TEST_FILE_FOLDER/$test_file" 2>/dev/null || stat -f %z "$TEST_FILE_FOLDER/$test_file" 2>/dev/null)

  run split_file "$TEST_FILE_FOLDER/$test_file" 4
  assert_success

  run upload_and_check_attributes "$test_file" "$file_size"
  assert_success
}

@test "REST - attributes - invalid param" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1001"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_attributes_invalid_param "$test_file"
  assert_success
}

@test "REST - attributes - checksum" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run add_and_check_checksum "$TEST_FILE_FOLDER/$test_file" "$test_file"
  assert_success
}

@test "REST - list objects v2 - invalid continuation token" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/993"
  fi
  test_file_two="test_file_2"
  test_file_three="test_file_3"
  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$test_file" "$test_file_two" "$test_file_three"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_three" "$BUCKET_ONE_NAME" "$test_file_three"
  assert_success

  run list_objects_check_params_get_token "$BUCKET_ONE_NAME" "$test_file" "$test_file_two" "TRUE"
  assert_success
  continuation_token=$output

  # interestingly, AWS appears to accept continuation tokens that are a few characters off, so have to remove three chars
  run list_objects_check_continuation_error "$BUCKET_ONE_NAME" "${continuation_token:0:${#continuation_token}-3}"
  assert_success
}

@test "REST - list objects v1 - no NextMarker without delimiter" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/999"
  fi
  test_file_two="test_file_2"
  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$test_file" "$test_file_two"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run list_objects_v1_check_nextmarker_empty "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - head object" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_etag_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success
  expected_etag=$output

  run get_etag_attribute_rest "$BUCKET_ONE_NAME" "$test_file" "$expected_etag"
  assert_success
}

@test "REST - delete objects - no content-md5 header" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1040"
  fi
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run delete_objects_no_content_md5_header "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - delete objects command" {
  test_file_two="test_file_two"
  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$test_file" "$test_file_two"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run verify_object_exists "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run verify_object_exists "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run delete_objects_verify_success "$BUCKET_ONE_NAME" "$test_file" "$test_file_two"
  assert_success

  run verify_object_not_found "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run verify_object_not_found "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success
}

@test "REST - put object w/STREAMING-AWS4-HMAC-SHA256-PAYLOAD without content length" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_chunked_payload_type_without_content_length "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - invalid 'Expires' parameter" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_check_expires_header "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObject with user permission - admin user" {
  run setup_bucket_file_and_user "$BUCKET_ONE_NAME" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"
  log 5 "username: $username, password: $password"

  run put_object_rest_with_user "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObject with no permission - 'user' user" {
  run setup_bucket_file_and_user "$BUCKET_ONE_NAME" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "user"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_with_user_and_code "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "403"
  assert_success
}

@test "REST - PutObject - user permission, bad signature" {
  run setup_bucket_file_and_user "$BUCKET_ONE_NAME" "$test_file" "$USERNAME_ONE" "$PASSWORD_ONE" "admin"
  assert_success
  username="${lines[${#lines[@]}-2]}"
  password="${lines[${#lines[@]}-1]}"

  run put_object_rest_user_bad_signature "$username" "$password" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObjectRetention - w/o request body" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1185"
  fi
  run setup_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run retention_rest_without_request_body "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObjectLegalHold - missing content-md5" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1311"
  fi
  run setup_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_legal_hold_without_content_md5 "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObjectLegalHold w/o payload" {
  run setup_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_legal_hold_without_payload "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObjectLegalHold - success" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1193"
  fi
  run setup_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run rest_check_legal_hold "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - copy object w/invalid copy source" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run copy_object_invalid_copy_source "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - copy object w/copy source and payload" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1242"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run copy_object_copy_source_and_payload "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "REST - range download and compare" {
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy" 2000000
  assert_success
}

@test "REST - put object, missing Content-Length" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1321"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_without_content_length "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "REST - put, get object, encoded name" {
  file_name=" \"<>\\^\`{}|+&?%"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$file_name"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$BUCKET_ONE_NAME" "$file_name/$file_name"
  assert_success

  run list_check_single_object "$BUCKET_ONE_NAME" "$file_name/$file_name"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$file_name" "$BUCKET_ONE_NAME" "$file_name/$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success

  run delete_object_rest "$BUCKET_ONE_NAME" "$file_name/$file_name"
  assert_success
}

@test "REST - GetObject w/STREAMING-AWS4-HMAC-SHA256-PAYLOAD type" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1352"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object_rest_with_invalid_streaming_type "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - PutObject w/x-amz-checksum-algorithm" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1356"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_with_unneeded_algorithm_param "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "crc32c"
  assert_success
}

@test "REST - empty message" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1249"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  echo -en "\r\n" > "$TEST_FILE_FOLDER/empty.txt"
  run send_via_openssl_with_timeout "$TEST_FILE_FOLDER/empty.txt"
  assert_success
}

@test "REST - deformed message" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1364"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  echo -en "abcdefg\r\n\r\n" > "$TEST_FILE_FOLDER/deformed.txt"
  run send_via_openssl_check_code_error_contains "$TEST_FILE_FOLDER/deformed.txt" 400 "BadRequest" "An error occurred when parsing the HTTP request."
  assert_success
}
