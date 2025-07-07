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

source ./tests/setup.sh
source ./tests/util/util_create_bucket.sh
source ./tests/util/util_file.sh
source ./tests/util/util_lock_config.sh
source ./tests/util/util_object.sh
source ./tests/util/util_setup.sh
source ./tests/util/util_tags.sh
source ./tests/util/util_users.sh
source ./tests/test_s3api_root_inner.sh
source ./tests/test_common.sh
source ./tests/test_common_acl.sh
source ./tests/commands/copy_object.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/get_bucket_versioning.sh
source ./tests/commands/get_object.sh
source ./tests/commands/get_object_attributes.sh
source ./tests/commands/get_object_legal_hold.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/get_object_retention.sh
source ./tests/commands/get_object_tagging.sh
source ./tests/commands/list_object_versions.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_policy.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object.sh
source ./tests/commands/put_object_legal_hold.sh
source ./tests/commands/put_object_lock_configuration.sh
source ./tests/commands/put_object_retention.sh
source ./tests/commands/put_public_access_block.sh
source ./tests/commands/select_object_content.sh
source ./tests/drivers/copy_object/copy_object_rest.sh

export RUN_USERS=true

# copy-object
@test "test_copy_object" {
  test_common_copy_object "s3api"
}

@test "test_copy_object_empty" {
  run copy_object_empty
  assert_success
}

# delete-object - tested with bucket cleanup before or after tests

# delete-object-tagging
@test "test_delete_object_tagging" {
  test_common_delete_object_tagging "s3api"
}

# delete-objects
@test "test_delete_objects" {
  test_delete_objects_s3api_root
}

# get-object
@test "test_get_object_full_range" {
  test_get_object_full_range_s3api_root
}

@test "test_get_object_invalid_range" {
  test_get_object_invalid_range_s3api_root
}

# get-object-attributes
@test "test_get_object_attributes" {
  test_get_object_attributes_s3api_root
}

@test "test_get_put_object_legal_hold" {
  test_get_put_object_legal_hold_s3api_root
}

@test "test_get_put_object_retention" {
  test_get_put_object_retention_s3api_root
}

# test listing a bucket's objects on versitygw
@test "test_list_objects" {
  test_common_list_objects "s3api"
}

@test "test-list-objects-delimiter" {
  folder_name="two"
  object_name="three"

  run create_test_folder "$folder_name"
  assert_success

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$folder_name/$object_name"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$folder_name/$object_name" "$BUCKET_ONE_NAME" "$folder_name/$object_name"
  assert_success

  run check_object_listing_with_prefixes "$BUCKET_ONE_NAME" "$folder_name" "$object_name"
  assert_success
}

@test "test_put_object" {
  test_put_object_s3api_root
}

# test adding and removing an object on versitygw
@test "test_put_object_with_data" {
  test_common_put_object_with_data "s3api"
}

@test "test_put_object_no_data" {
  test_common_put_object_no_data "s3api"
}

@test "test-presigned-url-utf8-chars" {
  test_common_presigned_url_utf8_chars "s3api"
}

@test "test_put_object_lock_configuration" {
  bucket_name=$BUCKET_ONE_NAME
  if [[ $RECREATE_BUCKETS == "true" ]]; then
    run delete_bucket "s3api" "$bucket_name"
    assert_success
    run create_bucket_object_lock_enabled "$bucket_name"
    assert_success
  fi
  local enabled="Enabled"
  local governance="GOVERNANCE"
  local days="1"

  run put_object_lock_configuration "$bucket_name" "$enabled" "$governance" "$days"
  assert_success "error putting object lock config"

  run get_and_check_object_lock_config "$bucket_name" "$enabled" "$governance" "$days"
  assert_success "error getting and checking object lock config"
}

@test "test_put_object_metadata" {
  test_key="x-test-data"
  test_value="test-value"

  object_one="object-one"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$object_one"
  assert_success

  object="$TEST_FILE_FOLDER"/"$object_one"
  run put_object_with_metadata "s3api" "$object" "$BUCKET_ONE_NAME" "$object_one" "$test_key" "$test_value"
  assert_success

  run object_exists "s3api" "$BUCKET_ONE_NAME" "$object_one"
  assert_success

  run get_object_metadata_and_check_keys "$BUCKET_ONE_NAME" "$object_one" "$test_key" "$test_value"
  assert_success
}

@test "test_retention_bypass" {
  test_retention_bypass_s3api_root
}

# test v1 s3api list objects command
@test "test-s3api-list-objects-v1" {
  test_s3api_list_objects_v1_s3api_root
}

# test v2 s3api list objects command
@test "test-s3api-list-objects-v2" {
  test_s3api_list_objects_v2_s3api_root
}

# test abilty to set and retrieve object tags
@test "test-set-get-object-tags" {
  test_common_set_get_object_tags "s3api"
}

# ensure that lists of files greater than a size of 1000 (pagination) are returned properly
#@test "test_list_objects_file_count" {
#  test_common_list_objects_file_count "s3api"
#}

# ensure that lists of files greater than a size of 1000 (pagination) are returned properly
#@test "test_list_objects_file_count" {
#  test_common_list_objects_file_count "s3api"
#}

#@test "test_filename_length" {
#  file_name=$(printf "%0.sa" $(seq 1 1025))
#  echo "$file_name"

#  create_test_files "$file_name" || created=$?
#  [[ $created -eq 0 ]] || fail "error creating file"

#  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local setup_result=$?
#  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

#  put_object "s3api" "$TEST_FILE_FOLDER"/"$file_name" "$BUCKET_ONE_NAME"/"$file_name" || local put_object=$?
#  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket"
#}


@test "test_ls_directory_object" {
  test_common_ls_directory_object "s3api"
}

@test "directory objects can't contain data" {
  if [ "$DIRECT" == "true" ]; then
    skip "for direct, directory objects can contain data (though discouraged)"
  fi
  test_file="a"

  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file/"
  assert_failure
  assert_output -p "Directory object contains data payload"
}

@test "objects containing data can't be copied to directory objects with same name" {
  # operation is legal (though discouraged) for direct
  if [ "$DIRECT" == "true" ]; then
    skip "for direct, directory objects can contain data (though discouraged)"
  fi
  test_file="a"

  run create_test_file "$test_file" 0
  assert_success

  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run attempt_copy_object_to_directory_with_same_name "$BUCKET_ONE_NAME" "$test_file" "$BUCKET_ONE_NAME/$test_file"
  assert_success
}

@test "directory object - create multipart upload" {
  run setup_bucket "$BUCKET_ONE_NAME"
  assert_success

  run create_multipart_upload_s3api "$BUCKET_ONE_NAME" "test_file/"
  assert_failure
  assert_output -p "Directory object contains data payload"
}

@test "s3api - --bypass-governance-retention w/o bucket w/object lock fails" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/1218"
  fi
  test_file="test_file"
  run setup_bucket_and_file "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run put_object "s3api" "$TEST_FILE_FOLDER/$test_file" "$BUCKET_ONE_NAME" "$test_file"
  assert_success

  run delete_object_bypass_retention "$BUCKET_ONE_NAME" "$test_file" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"
  assert_failure
  assert_output -p "InvalidArgument"
  assert_output -p "x-amz-bypass-governance-retention is only applicable"
}

