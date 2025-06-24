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

source ./tests/commands/delete_objects.sh
source ./tests/commands/list_objects_v2.sh
source ./tests/commands/list_parts.sh
source ./tests/util/util_get_bucket_acl.sh
source ./tests/util/util_get_object_attributes.sh
source ./tests/util/util_get_object_retention.sh
source ./tests/util/util_head_object.sh
source ./tests/util/util_legal_hold.sh
source ./tests/util/util_list_objects.sh
source ./tests/util/util_setup.sh

test_delete_objects_s3api_root() {
  local object_one="test-file-one"
  local object_two="test-file-two"
  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$object_one" "$object_two"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER"/"$object_one" "$BUCKET_ONE_NAME" "$object_one"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER"/"$object_two" "$BUCKET_ONE_NAME" "$object_two"
  assert_success

  run delete_objects "$BUCKET_ONE_NAME" "$object_one" "$object_two"
  assert_success

  run object_exists "s3api" "$BUCKET_ONE_NAME" "$object_one"
  assert_failure 1

  run object_exists "s3api" "$BUCKET_ONE_NAME" "$object_two"
  assert_failure 1
}

test_get_object_full_range_s3api_root() {
  bucket_file="bucket_file"
  echo -n "0123456789" > "$TEST_FILE_FOLDER/$bucket_file"

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run get_object_with_range "$BUCKET_ONE_NAME" "$bucket_file" "bytes=9-15" "$TEST_FILE_FOLDER/$bucket_file-range"
  assert_success

  assert [ "$(cat "$TEST_FILE_FOLDER/$bucket_file-range")" == "9" ]
}

test_get_object_invalid_range_s3api_root() {
  bucket_file="bucket_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run get_object_with_range "$BUCKET_ONE_NAME" "$bucket_file" "bytes=0-0" "$TEST_FILE_FOLDER/$bucket_file-range"
  assert_success
}

test_put_object_s3api_root() {
  bucket_file="bucket_file"

  run create_test_files "$bucket_file"
  assert_success

  run setup_buckets "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run copy_object "s3api" "$BUCKET_ONE_NAME/$bucket_file" "$BUCKET_TWO_NAME" "$bucket_file"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER/${bucket_file}_copy"
  assert_success
}

test_get_object_attributes_s3api_root() {
  bucket_file="bucket_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run get_and_check_object_size "$BUCKET_ONE_NAME" "$bucket_file" 10
  assert_success
}

test_get_put_object_legal_hold_s3api_root() {
  bucket_file="bucket_file"
  username=$USERNAME_ONE
  password=$PASSWORD_ONE

  run legal_hold_retention_setup "$username" "$password" "$bucket_file"
  assert_success

  run get_check_object_lock_config_enabled "$BUCKET_ONE_NAME"
  assert_success

  run put_object_legal_hold "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "ON"
  assert_success

  run get_and_check_legal_hold "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "ON"
  assert_success

  echo "fdkljafajkfs" > "$TEST_FILE_FOLDER/$bucket_file"
  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$password"
  assert_failure
  assert_output --partial "Object is WORM protected and cannot be overwritten"

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$password"
  assert_failure 1
  # shellcheck disable=SC2154
  assert_output --partial "Object is WORM protected and cannot be overwritten"

  run put_object_legal_hold "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "OFF"
  assert_success

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$password"
  assert_success
}

test_get_put_object_retention_s3api_root() {
  bucket_file="bucket_file"
  username=$USERNAME_ONE
  secret_key=$PASSWORD_ONE

  run legal_hold_retention_setup "$username" "$secret_key" "$bucket_file"
  assert_success

  run get_check_object_lock_config_enabled "$BUCKET_ONE_NAME"
  assert_success

  if [[ "$OSTYPE" == "darwin"* ]]; then
    retention_date=$(TZ="UTC" date -v+5S +"%Y-%m-%dT%H:%M:%S")
  else
    retention_date=$(TZ="UTC" date -d "+5 seconds" +"%Y-%m-%dT%H:%M:%S")
  fi
  log 5 "retention date: $retention_date"

  run put_object_retention "$BUCKET_ONE_NAME" "$bucket_file" "GOVERNANCE" "$retention_date"
  assert_success

  run get_check_object_retention "$BUCKET_ONE_NAME" "$bucket_file" "$retention_date"
  assert_success

  echo "fdkljafajkfs" > "$TEST_FILE_FOLDER/$bucket_file"
  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key"
  assert_failure
  # shellcheck disable=SC2154
  assert_output --partial "Object is WORM protected and cannot be overwritten"

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key"
  assert_failure
  # shellcheck disable=SC2154
  assert_output --partial "Object is WORM protected and cannot be overwritten"
}

test_retention_bypass_s3api_root() {
  bucket_file="bucket_file"
  username=$USERNAME_ONE
  secret_key=$PASSWORD_ONE
  policy_file="policy_file"

  run legal_hold_retention_setup "$username" "$secret_key" "$bucket_file"
  assert_success

  run get_check_object_lock_config_enabled "$BUCKET_ONE_NAME"
  assert_success

  if [[ "$OSTYPE" == "darwin"* ]]; then
    retention_date=$(TZ="UTC" date -v+30S +"%Y-%m-%dT%H:%M:%S")
  else
    retention_date=$(TZ="UTC" date -d "+30 seconds" +"%Y-%m-%dT%H:%M:%S")
  fi
  log 5 "retention date: $retention_date"

  run put_object_retention "$BUCKET_ONE_NAME" "$bucket_file" "GOVERNANCE" "$retention_date"
  assert_success

  run delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_failure 1

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "Allow" "$username" \
    "[\"s3:BypassGovernanceRetention\",\"s3:DeleteObject\"]" "arn:aws:s3:::$BUCKET_ONE_NAME/*"
  assert_success

  run put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$policy_file"
  assert_success

  run delete_object_bypass_retention "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key"
  assert_success
}

legal_hold_retention_setup() {
  assert [ $# -eq 3 ]

  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  run setup_user "$1" "$2" "user"
  assert_success

  run create_test_file "$3"
  assert_success

  #create_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error creating bucket"
  if [[ $RECREATE_BUCKETS == "true" ]]; then
    run create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"
    assert_success
  fi

  run change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$1"
  assert_success

  run put_object_with_user "s3api" "$TEST_FILE_FOLDER/$3" "$BUCKET_ONE_NAME" "$3" "$1" "$2"
  assert_success
}

test_s3api_list_objects_v1_s3api_root() {
  local object_one="test-file-one"
  local object_two="test-file-two"
  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$object_one" "$object_two"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER"/"$object_one" "$BUCKET_ONE_NAME" "$object_one"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER"/"$object_two" "$BUCKET_ONE_NAME" "$object_two"
  assert_success

  run list_check_objects_v1 "$BUCKET_ONE_NAME" "$object_one" 10 "$object_two" 10
  assert_success
}

test_s3api_list_objects_v2_s3api_root() {
  local object_one="test-file-one"
  local object_two="test-file-two"
  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$object_one" "$object_two"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER"/"$object_one" "$BUCKET_ONE_NAME" "$object_one"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER"/"$object_two" "$BUCKET_ONE_NAME" "$object_two"
  assert_success

  run list_check_objects_v2 "$BUCKET_ONE_NAME" "$object_one" 10 "$object_two" 10
  assert_success
}
