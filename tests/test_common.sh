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
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/file.sh
source ./tests/drivers/params.sh
source ./tests/util/util_file.sh
source ./tests/util/util_list_buckets.sh
source ./tests/util/util_object.sh
source ./tests/util/util_policy.sh
source ./tests/util/util_presigned_url.sh

# param:  command type
# fail on test failure
test_common_multipart_upload() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name bucket_file <<< "$output"

  if [ "$1" == 's3' ]; then
    run copy_file_locally "$TEST_FILE_FOLDER/$bucket_file" "$TEST_FILE_FOLDER/$bucket_file-copy"
    assert_success
  fi

  run put_object "$1" "$TEST_FILE_FOLDER/$bucket_file" "$bucket_name" "$bucket_file"
  assert_success

  if [ "$1" == 's3' ]; then
    run move_file_locally "$TEST_FILE_FOLDER/$bucket_file-copy" "$TEST_FILE_FOLDER/$bucket_file"
    assert_success
  fi

  log 5 "file: $TEST_FILE_FOLDER/$bucket_file, bucket: $bucket_name"
  run download_and_compare_file "$TEST_FILE_FOLDER/$bucket_file" "$bucket_name" "$bucket_file" "$TEST_FILE_FOLDER/$bucket_file-copy"
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

  run bucket_cleanup_if_bucket_exists_v2 "$BUCKET_ONE_NAME"
  assert_success

  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run create_bucket "$1" "$bucket_name"
  assert_success

  run bucket_exists "$bucket_name"
  assert_success
  assert_output "true"

  run delete_bucket "$1" "$bucket_name"
  assert_success

  run bucket_exists "$bucket_name"
  assert_failure 1
  assert_output "false"
}

test_common_copy_object() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run create_test_file_v2
  assert_success
  object_name=$output

  run setup_buckets_v3 "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success
  read -r bucket_one bucket_two <<< "$output"

  if [[ $1 == 's3' ]]; then
    run copy_object "$1" "$TEST_FILE_FOLDER/$object_name" "$bucket_one" "$object_name"
    assert_success
  else
    run put_object "$1" "$TEST_FILE_FOLDER/$object_name" "$bucket_one" "$object_name"
    assert_success
  fi
  if [[ $1 == 's3' ]]; then
    run copy_object "$1" "s3://$bucket_one/$object_name" "$bucket_two" "$object_name"
    assert_success
  else
    run copy_object "$1" "$bucket_one/$object_name" "$bucket_two" "$object_name"
    assert_success
  fi
  run download_and_compare_file "$TEST_FILE_FOLDER/$object_name" "$bucket_two" "$object_name" "$TEST_FILE_FOLDER/$object_name-copy"
  assert_success
}

# param:  client
# fail on error
test_common_put_object_with_data() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run create_test_file_v2
  assert_success
  object_name=$output

  test_common_put_object "$1" "$object_name"
}

# param:  client
# fail on error
test_common_put_object_no_data() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run create_test_file_v2 0
  assert_success
  object_name="$output"

  test_common_put_object "$1" "$object_name"
}

# params:  client, filename
# fail on test failure
test_common_put_object() {
  run assert_param_count "client type, file" 2 "$#"
  assert_success

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  # s3 erases file locally, so we need to copy it first
  if [ "$1" == 's3' ]; then
    run copy_file_locally "$TEST_FILE_FOLDER/$2" "$TEST_FILE_FOLDER/${2}-copy"
    assert_success
  fi

  run put_object "$1" "$TEST_FILE_FOLDER/$2" "$bucket_name" "$2"
  assert_success

  if [ "$1" == 's3' ]; then
    run move_file_locally "$TEST_FILE_FOLDER/${2}-copy" "$TEST_FILE_FOLDER/$2"
    assert_success
  fi

  run download_and_compare_file "$TEST_FILE_FOLDER/$2" "$bucket_name" "$2" "$TEST_FILE_FOLDER/${2}-copy"
  assert_success

  run delete_object "$1" "$bucket_name" "$2"
  assert_success

  run object_exists "$1" "$bucket_name" "$2"
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

  run setup_buckets_v3 "$BUCKET_ONE_NAME" "$BUCKET_TWO_NAME"
  assert_success
  read -r bucket_one bucket_two <<< "$output"

  run list_and_check_buckets "$1" "$bucket_one" "$bucket_two"
  assert_success
}

test_common_list_objects() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run setup_bucket_and_files_v3 "$BUCKET_ONE_NAME" 2
  assert_success
  read -r bucket_name object_one object_two <<< "$output"

  run put_object "$1" "$TEST_FILE_FOLDER/$object_one" "$bucket_name" "$object_one"
  assert_success

  run put_object "$1" "$TEST_FILE_FOLDER/$object_two" "$bucket_name" "$object_two"
  assert_success

  run list_check_objects_common "$1" "$bucket_name" "$object_one" "$object_two"
  assert_success
}

test_common_set_get_delete_bucket_tags() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  local key="test_key"
  local value="test_value"

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run verify_no_bucket_tags "$1" "$bucket_name"
  assert_success

  run put_bucket_tagging "$1" "$bucket_name" $key $value
  assert_success

  run get_and_check_bucket_tags "$bucket_name" "$key" "$value"
  assert_success

  run delete_bucket_tagging "$1" "$bucket_name"
  assert_success

  run verify_no_bucket_tags "$1" "$bucket_name"
  assert_success
}

test_common_set_get_object_tags() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name bucket_file <<< "$output"

  local key="test_key"
  local value="test_value"

  run put_object "$1" "$TEST_FILE_FOLDER"/"$bucket_file" "$bucket_name" "$bucket_file"
  assert_success

  run verify_no_object_tags "$1" "$bucket_name" "$bucket_file"
  assert_success

  run put_object_tagging "$1" "$bucket_name" "$bucket_file" "$key" "$value"
  assert_success

  run check_verify_object_tags "$1" "$bucket_name" "$bucket_file" "$key" "$value"
  assert_success
}

test_common_presigned_url_utf8_chars() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run get_file_names 2
  assert_success
  read -r file_header bucket_file_copy <<< "$output"

  local bucket_file="${file_header}-$%^&*;"
  run create_test_file "$bucket_file"
  assert_success

  run dd if=/dev/urandom of="$TEST_FILE_FOLDER/$bucket_file" bs=5M count=1
  assert_success

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run put_object "$1" "$TEST_FILE_FOLDER"/"$bucket_file" "$bucket_name" "$bucket_file"
  assert_success

  run create_check_presigned_url "$1" "$bucket_name" "$bucket_file" "$TEST_FILE_FOLDER/$bucket_file_copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER"/"$bucket_file" "$TEST_FILE_FOLDER"/"$bucket_file_copy"
  assert_success
}

test_common_list_objects_file_count() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run create_test_file_count 1001
  assert_success

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run put_object_multiple "$1" "$TEST_FILE_FOLDER/file_*" "$bucket_name"
  assert_success

  run list_objects_check_file_count "$1" "$bucket_name" 1001
  assert_success
}

test_common_delete_object_tagging() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  tag_key="key"
  tag_value="value"

  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name bucket_file <<< "$output"

  run put_object "$1" "$TEST_FILE_FOLDER"/"$bucket_file" "$bucket_name" "$bucket_file"
  assert_success

  run put_object_tagging "$1" "$bucket_name" "$bucket_file" "$tag_key" "$tag_value"
  assert_success

  run get_and_verify_object_tags "$1" "$bucket_name" "$bucket_file" "$tag_key" "$tag_value"
  assert_success

  run delete_object_tagging "$1" "$bucket_name" "$bucket_file"
  assert_success

  run check_object_tags_empty "$1" "$bucket_name" "$bucket_file"
  assert_success
}

test_common_get_bucket_location() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  run get_check_bucket_location_various "$1" "$bucket_name"
  assert_success
}

test_common_get_put_delete_bucket_policy() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name=$output

  effect="Allow"
  principal="*"
  action="s3:GetObject"
  resource="arn:aws:s3:::$bucket_name/*"

  run setup_policy_with_single_statement_v2 "2012-10-17" "$effect" "$principal" "$action" "$resource"
  assert_success
  policy_file="$output"

  run check_for_empty_policy "$1" "$bucket_name"
  assert_success

  run put_bucket_policy "$1" "$bucket_name" "$TEST_FILE_FOLDER"/"$policy_file"
  assert_success

  run get_and_check_policy "$1" "$bucket_name" "$effect" "$principal" "$action" "$resource"
  assert_success

  run delete_bucket_policy "$1" "$bucket_name"
  assert_success

  run check_for_empty_policy "$1" "$bucket_name"
  assert_success
}

test_common_ls_directory_object() {
  run assert_param_count "client type" 1 "$#"
  assert_success

  run create_test_file_v2 0
  assert_success
  test_file="$output"

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  if [ "$1" == 's3cmd' ]; then
    put_object_client="s3api"
  else
    put_object_client="$1"
  fi
  run put_object "$put_object_client" "$TEST_FILE_FOLDER/$test_file" "$bucket_name" "$test_file/"
  assert_success "error putting test file folder"

  run list_and_check_directory_obj "$1" "$bucket_name" "$test_file"
  assert_success "error listing and checking directory object"
}
