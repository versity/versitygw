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
source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/util/util_acl.sh
source ./tests/util/util_attributes.sh
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

  run get_object "rest" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
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

  run bucket_cleanup_if_bucket_exists "s3api" "$BUCKET_ONE_NAME"
  assert_success
  # in static bucket config, bucket will still exist
  if ! bucket_exists "rest" "$BUCKET_ONE_NAME"; then
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

@test "REST - multipart upload create then abort" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_abort_multipart_upload_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - multipart upload create, list parts" {
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$test_file" 4
  assert_success

  run upload_check_parts "$BUCKET_ONE_NAME" "$test_file" \
    "$TEST_FILE_FOLDER/$test_file-0" "$TEST_FILE_FOLDER/$test_file-1" "$TEST_FILE_FOLDER/$test_file-2" "$TEST_FILE_FOLDER/$test_file-3"
  assert_success

  run get_object "rest" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - get object attributes" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1000"
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

@test "REST - get policy w/o policy" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/959"
  fi

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run get_and_check_no_policy_error "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - put policy" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run setup_user_versitygw_or_direct "$USERNAME_ONE" "$PASSWORD_ONE" "user" "$BUCKET_ONE_NAME"
  assert_success
  log 5 "username: ${lines[1]}"
  log 5 "password: ${lines[2]}"

  sleep 5

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/policy_file.txt" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success

  run put_and_check_policy_rest "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/policy_file.txt" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - list objects v2 - invalid continuation token" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/993"
  fi
  test_file_two="test_file_2"
  test_file_three="test_file_3"
  run setup_bucket_and_files "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_two" "$test_file_three"
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
  run setup_bucket "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_two"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two"
  assert_success

  run list_objects_v1_check_nextmarker_empty "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - complete upload - invalid part" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1008"
  fi
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_upload_finish_wrong_etag "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - upload part copy" {
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_upload_part_copy_rest "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success

  run download_and_compare_file "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
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

@test "REST - HeadObject - default crc64nvme checksum" {
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_default_checksum "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file"
  assert_success
}

@test "REST - POST call on root endpoint" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1036"
  fi
  run delete_object_empty_bucket_check_error
  assert_success
}

@test "REST - delete objects - no content-md5 header" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1040"
  fi
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
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
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1043"
  fi
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object_rest_chunked_payload_type_without_content_length "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - HeadObject does not return 405 with versioning, after file deleted" {
  if [ "$RECREATE_BUCKETS" == "false" ] || [[ ( -z "$VERSIONING_DIR" ) && ( "$DIRECT" != "true" ) ]]; then
    skip
  fi
  run bucket_cleanup_if_bucket_exists "s3api" "$BUCKET_ONE_NAME"
  assert_success

  # in static bucket config, bucket will still exist
  if ! bucket_exists "rest" "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run create_test_files "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run delete_object "s3api" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run verify_object_not_found "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - HeadObject returns 405 when querying DeleteMarker" {
  if [ "$RECREATE_BUCKETS" == "false" ] || [[ ( -z "$VERSIONING_DIR" ) && ( "$DIRECT" != "true" ) ]]; then
    skip
  fi
  run bucket_cleanup_if_bucket_exists "s3api" "$BUCKET_ONE_NAME"
  assert_success

  # in static bucket config, bucket will still exist
  if ! bucket_exists "rest" "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run create_test_files "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run delete_object "s3api" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_delete_marker_and_verify_405 "$BUCKET_ONE_NAME" "$test_file"
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

@test "REST - PutObjectLegalHold w/o payload" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1191"
  fi
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
