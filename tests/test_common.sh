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

source ./tests/setup.sh
source ./tests/util/util_acl.sh
source ./tests/util/util_bucket_location.sh
source ./tests/util/util_file.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_object.sh
source ./tests/util/util_policy.sh
source ./tests/util/util_presigned_url.sh
source ./tests/util/util_setup.sh
source ./tests/commands/copy_object.sh
source ./tests/commands/delete_bucket_tagging.sh
source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_location.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/get_object.sh
source ./tests/commands/get_object_tagging.sh
source ./tests/commands/list_buckets.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_tagging.sh
source ./tests/commands/put_object_tagging.sh
source ./tests/commands/put_object.sh
source ./tests/commands/put_public_access_block.sh
source ./tests/drivers/params.sh

# param:  command type
# fail on test failure
test_common_multipart_upload() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  bucket_file="largefile"
  run setup_bucket_and_large_file "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  if [ "$1" == 's3' ]; then
    run copy_file_locally "$TEST_FILE_FOLDER/$bucket_file" "$TEST_FILE_FOLDER/$bucket_file-copy"
    assert_success
  fi

  run put_object "$1" "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  if [ "$1" == 's3' ]; then
    run move_file_locally "$TEST_FILE_FOLDER/$bucket_file-copy" "$TEST_FILE_FOLDER/$bucket_file"
    assert_success
  fi

  run download_and_compare_file "$TEST_FILE_FOLDER/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER/$bucket_file-copy"
  assert_success
}

# common test for creating, deleting buckets
# param:  "aws" or "s3cmd"
# pass if buckets are properly listed, fail if not
test_common_create_delete_bucket() {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  run assert_param_count "client type" 1 "$#"
  assert_success

  run bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  run create_bucket "$1" "$BUCKET_ONE_NAME"
  assert_success

  run bucket_exists "$BUCKET_ONE_NAME"
  assert_success

  run delete_bucket "$1" "$BUCKET_ONE_NAME"
  assert_success
}

test_common_copy_object() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local object_name="test-object"
  run create_test_file "$object_name"
  assert_success

  run setup_buckets "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  if [[ $1 == 's3' ]]; then
    run copy_object "$1" "$TEST_FILE_FOLDER/$object_name" "$BUCKET_ONE_NAME" "$object_name"
    assert_success
  else
    run put_object "$1" "$TEST_FILE_FOLDER/$object_name" "$BUCKET_ONE_NAME" "$object_name"
    assert_success
  fi
  if [[ $1 == 's3' ]]; then
    run copy_object "$1" "s3://$BUCKET_ONE_NAME/$object_name" "$BUCKET_TWO_NAME" "$object_name"
    assert_success
  else
    run copy_object "$1" "$BUCKET_ONE_NAME/$object_name" "$BUCKET_TWO_NAME" "$object_name"
    assert_success
  fi
  run download_and_compare_file "$TEST_FILE_FOLDER/$object_name" "$BUCKET_TWO_NAME" "$object_name" "$TEST_FILE_FOLDER/$object_name-copy"
  assert_success
}

# param:  client
# fail on error
test_common_put_object_with_data() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local object_name="test-object"
  run create_test_file "$object_name"
  assert_success

  test_common_put_object "$1" "$object_name"
}

# param:  client
# fail on error
test_common_put_object_no_data() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local object_name="test-object"
  run create_test_file "$object_name" 0
  assert_success

  test_common_put_object "$1" "$object_name"
}

# params:  client, filename
# fail on test failure
test_common_put_object() {
  run assert_param_count "client type, file" 2 "$#"
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  # s3 erases file locally, so we need to copy it first
  if [ "$1" == 's3' ]; then
    run copy_file_locally "$TEST_FILE_FOLDER/$2" "$TEST_FILE_FOLDER/${2}-copy"
    assert_success
  fi

  run put_object "$1" "$TEST_FILE_FOLDER/$2" "$BUCKET_ONE_NAME" "$2"
  assert_success

  if [ "$1" == 's3' ]; then
    run move_file_locally "$TEST_FILE_FOLDER/${2}-copy" "$TEST_FILE_FOLDER/$2"
    assert_success
  fi

  run download_and_compare_file "$TEST_FILE_FOLDER/$2" "$BUCKET_ONE_NAME" "$2" "$TEST_FILE_FOLDER/${2}-copy"
  assert_success

  run delete_object "$1" "$BUCKET_ONE_NAME" "$2"
  assert_success

  run object_exists "$1" "$BUCKET_ONE_NAME" "$2"
  assert_failure 1
}

test_common_put_get_object() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local object_name="test-object"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$object_name"
  assert_success

  if [[ $1 == 's3' ]]; then
    run copy_object "$1" "$TEST_FILE_FOLDER/$object_name" "$BUCKET_ONE_NAME" "$object_name"
    assert_success
  else
    run put_object "$1" "$TEST_FILE_FOLDER/$object_name" "$BUCKET_ONE_NAME" "$object_name"
    assert_success
  fi
  run object_exists "$1" "$BUCKET_ONE_NAME" "$object_name"
  assert_success

  run get_object "$1" "$BUCKET_ONE_NAME" "$object_name" "$TEST_FILE_FOLDER/${object_name}-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER/$object_name" "$TEST_FILE_FOLDER/${object_name}-copy"
  assert_success
}

# common test for listing buckets
# param:  "aws" or "s3cmd"
# pass if buckets are properly listed, fail if not
test_common_list_buckets() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run setup_buckets "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success

  run list_and_check_buckets "$1" "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success
}

test_common_list_objects() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  object_one="test-file-one"
  object_two="test-file-two"
  run setup_bucket_and_files "$BUCKET_ONE_NAME" "$object_one" "$object_two"
  assert_success

  run put_object "$1" "$TEST_FILE_FOLDER"/$object_one "$BUCKET_ONE_NAME" "$object_one"
  assert_success

  run put_object "$1" "$TEST_FILE_FOLDER"/$object_two "$BUCKET_ONE_NAME" "$object_two"
  assert_success

  run list_check_objects_common "$1" "$BUCKET_ONE_NAME" "$object_one" "$object_two"
  assert_success
}

test_common_set_get_delete_bucket_tags() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local key="test_key"
  local value="test_value"

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run verify_no_bucket_tags "$1" "$BUCKET_ONE_NAME"
  assert_success

  run put_bucket_tagging "$1" "$BUCKET_ONE_NAME" $key $value
  assert_success

  run get_and_check_bucket_tags "$BUCKET_ONE_NAME" "$key" "$value"
  assert_success

  run delete_bucket_tagging "$1" "$BUCKET_ONE_NAME"
  assert_success

  run verify_no_bucket_tags "$1" "$BUCKET_ONE_NAME"
  assert_success
}

test_common_set_get_object_tags() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local bucket_file="bucket-file"
  local key="test_key"
  local value="test_value"

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run put_object "$1" "$TEST_FILE_FOLDER"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run verify_no_object_tags "$1" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run put_object_tagging "$1" "$BUCKET_ONE_NAME" $bucket_file $key $value
  assert_success

  run check_verify_object_tags "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$key" "$value"
  assert_success
}

test_common_presigned_url_utf8_chars() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local bucket_file="my-$%^&*;"
  local bucket_file_copy="bucket-file-copy"

  run create_test_file "$bucket_file"
  assert_success
  run dd if=/dev/urandom of="$TEST_FILE_FOLDER/$bucket_file" bs=5M count=1
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run put_object "$1" "$TEST_FILE_FOLDER"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run create_check_presigned_url "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER/$bucket_file_copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER"/"$bucket_file" "$TEST_FILE_FOLDER"/"$bucket_file_copy"
  assert_success
}

test_common_list_objects_file_count() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run create_test_file_count 1001
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run put_object_multiple "$1" "$TEST_FILE_FOLDER/file_*" "$BUCKET_ONE_NAME"
  assert_success

  run list_objects_check_file_count "$1" "$BUCKET_ONE_NAME" 1001
  assert_success
}

test_common_delete_object_tagging() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  bucket_file="bucket_file"
  tag_key="key"
  tag_value="value"

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run put_object "$1" "$TEST_FILE_FOLDER"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run put_object_tagging "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$tag_key" "$tag_value"
  assert_success

  run get_and_verify_object_tags "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$tag_key" "$tag_value"
  assert_success

  run delete_object_tagging "$1" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success

  run check_object_tags_empty "$1" "$BUCKET_ONE_NAME" "$bucket_file"
  assert_success
}

test_common_get_bucket_location() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run get_check_bucket_location "$1" "$BUCKET_ONE_NAME"
  assert_success
}

test_common_get_put_delete_bucket_policy() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  policy_file="policy_file"

  run create_test_file "$policy_file"
  assert_success

  effect="Allow"
  principal="*"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"

  run setup_policy_with_single_statement "$TEST_FILE_FOLDER/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success
  log 5 "POLICY: $(cat "$TEST_FILE_FOLDER/$policy_file")"

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run check_for_empty_policy "$1" "$BUCKET_ONE_NAME"
  assert_success

  run put_bucket_policy "$1" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER"/"$policy_file"
  assert_success

  run get_and_check_policy "$1" "$BUCKET_ONE_NAME" "$effect" "$principal" "$action" "$resource"
  assert_success

  run delete_bucket_policy "$1" "$BUCKET_ONE_NAME"
  assert_success

  run check_for_empty_policy "$1" "$BUCKET_ONE_NAME"
  assert_success
}

test_common_ls_directory_object() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  test_file="a"

  run create_test_file "$test_file" 0
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  if [ "$1" == 's3cmd' ]; then
    put_object_client="s3api"
  else
    put_object_client="$1"
  fi
  run put_object "$put_object_client" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file/"
  assert_success "error putting test file folder"

  run list_and_check_directory_obj "$1" "$test_file"
  assert_success "error listing and checking directory object"
}
