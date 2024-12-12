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
source ./tests/util/util.sh
source ./tests/util/util_acl.sh
source ./tests/util/util_attributes.sh
source ./tests/util/util_legal_hold.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_list_objects.sh
source ./tests/util/util_list_parts.sh
source ./tests/util/util_lock_config.sh
source ./tests/util/util_ownership.sh
source ./tests/util/util_policy.sh
source ./tests/util/util_public_access_block.sh
source ./tests/util/util_rest.sh
source ./tests/util/util_tags.sh
source ./tests/util/util_time.sh
source ./tests/util/util_versioning.sh

export RUN_USERS=true

@test "test_rest_list_objects" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test_file"
  run create_test_files "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run list_check_objects_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_rest_list_buckets" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run list_check_buckets_rest
  assert_success
}

@test "test_rest_delete_object" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test_file"
  run create_test_files "$test_file"
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
  test_file="test_file"
  test_key="TestKey"
  test_value="TestValue"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_test_files "$test_file"
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
  test_file="test_file"
  test_key="TestKey"
  test_value="TestValue"

  run bucket_cleanup_if_bucket_exists "s3api" "$BUCKET_ONE_NAME"
  assert_success
  # in static bucket config, bucket will still exist
  if ! bucket_exists "s3api" "$BUCKET_ONE_NAME"; then
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

@test "REST - check, enable, suspend versioning" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  log 5 "get versioning"

  run check_versioning_status_rest "$BUCKET_ONE_NAME" ""
  assert_success

  run put_bucket_versioning_rest "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run check_versioning_status_rest "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run put_bucket_versioning_rest "$BUCKET_ONE_NAME" "Suspended"
  assert_success

  run check_versioning_status_rest "$BUCKET_ONE_NAME" "Suspended"
  assert_success
}

@test "test_rest_set_get_lock_config" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run check_no_object_lock_config_rest "$BUCKET_ONE_NAME"
  assert_success

  run bucket_cleanup_if_bucket_exists "s3api" "$BUCKET_ONE_NAME"
  assert_success

  # in static bucket config, bucket will still exist
  if ! bucket_exists "s3api" "$BUCKET_ONE_NAME"; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run check_object_lock_config_enabled_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "test_rest_versioning" {
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    sleep 10
  fi

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_and_check_versions_rest "$BUCKET_ONE_NAME" "$test_file" "1" "true" "true"
  assert_success

  run put_bucket_versioning "s3api" "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run get_and_check_versions_rest "$BUCKET_ONE_NAME" "$test_file" "1" "true" "true"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_and_check_versions_rest "$BUCKET_ONE_NAME" "$test_file" "2" "true" "false" "false" "true"
  assert_success
}

@test "versioning - add version, then delete and check for marker" {
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "rest" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_versioning "s3api" "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run delete_object_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_versions_after_file_deletion "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "versioning - retrieve after delete" {
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_bucket_versioning "s3api" "$BUCKET_ONE_NAME" "Enabled"
  assert_success

  run delete_object "s3api" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_failure
}

@test "REST - legal hold, get without config" {
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_legal_hold_without_lock_enabled "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - multipart upload create then abort" {
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_abort_multipart_upload_rest "$BUCKET_ONE_NAME" "$test_file"
  assert_success
}

@test "REST - multipart upload create, list parts" {
  test_file="test_file"

  run create_large_file "$test_file"
  assert_success

  run split_file "$TEST_FILE_FOLDER/$test_file" 4
  assert_success

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run upload_check_parts "$BUCKET_ONE_NAME" "$test_file" \
    "$TEST_FILE_FOLDER/$test_file-0" "$TEST_FILE_FOLDER/$test_file-1" "$TEST_FILE_FOLDER/$test_file-2" "$TEST_FILE_FOLDER/$test_file-3"
  assert_success

  run get_object "s3api" "$BUCKET_ONE_NAME" "$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$test_file" "$TEST_FILE_FOLDER/$test_file-copy"
  assert_success
}

@test "REST - get object attributes" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/916"
  fi
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_large_file "$test_file"
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
    skip "https://github.com/versity/versitygw/issues/917"
  fi
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run check_attributes_invalid_param "$test_file"
  assert_success
}

@test "REST - attributes - checksum" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/928"
  fi
  test_file="test_file"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run create_test_file "$test_file"
  assert_success

  run add_and_check_checksum "$TEST_FILE_FOLDER/$test_file" "$test_file"
  assert_success
}

@test "REST - bucket tagging - no tags" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run verify_no_bucket_tags_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - bucket tagging - tags" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/932"
  fi
  test_key="testKey"
  test_value="testValue"

  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run add_verify_bucket_tags_rest "$BUCKET_ONE_NAME" "$test_key" "$test_value"
  assert_success
}

@test "REST - get, put bucket ownership controls" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run get_and_check_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerEnforced"
  assert_success

  run put_bucket_ownership_controls_rest "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run get_and_check_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
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
  log 5 "username: ${lines[0]}"
  log 5 "password: ${lines[1]}"

  sleep 5

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/policy_file.txt" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success

  run put_and_check_policy_rest "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/policy_file.txt" "Allow" "$USERNAME_ONE" "s3:PutBucketTagging" "arn:aws:s3:::$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - get ACL" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/971"
  fi
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  run get_and_check_acl_rest "$BUCKET_ONE_NAME"
  assert_success
}

@test "REST - put ACL" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test_file"
  run create_test_files "$test_file"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run setup_acl "$TEST_FILE_FOLDER/acl-file.txt" "$user_canonical_id" "READ" "$canonical_id"
  assert_success

  run list_objects_with_user_rest_verify_access_denied "$BUCKET_ONE_NAME" "$username" "$password"
  assert_success

  run put_acl_rest "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/acl-file.txt"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    sleep 5
  fi

  run list_objects_with_user_rest_verify_success "$BUCKET_ONE_NAME" "$username" "$password" "$test_file"
  assert_success
}

@test "REST - put public-read canned acl" {
  run setup_bucket "s3api" "$BUCKET_ONE_NAME"
  assert_success

  test_file="test_file"
  run create_test_files "$test_file"
  assert_success

  run put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run create_versitygw_acl_user_or_get_direct_user "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  canonical_id=${lines[0]}
  user_canonical_id=${lines[1]}
  username=${lines[2]}
  password=${lines[3]}

  run list_objects_with_user_rest_verify_access_denied "$BUCKET_ONE_NAME" "$username" "$password"
  assert_success

  run setup_acl "$TEST_FILE_FOLDER/acl-file.txt" "$user_canonical_id" "READ" "$canonical_id"
  assert_success

  if [ "$DIRECT" == "true" ]; then
    run allow_public_access "$BUCKET_ONE_NAME"
    assert_success
  fi
  run put_acl_rest "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/acl-file.txt"
  assert_success

  run list_objects_with_user_rest_verify_success "$BUCKET_ONE_NAME" "$username" "$password" "$test_file"
  assert_success
}
