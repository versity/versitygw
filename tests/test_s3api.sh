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
source ./tests/util.sh
source ./tests/util_aws.sh
source ./tests/util_create_bucket.sh
source ./tests/util_file.sh
source ./tests/util_lock_config.sh
source ./tests/util_multipart.sh
source ./tests/util_tags.sh
source ./tests/util_users.sh
source ./tests/test_aws_root_inner.sh
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
source ./tests/commands/list_multipart_uploads.sh
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

export RUN_USERS=true

# abort-multipart-upload
@test "test_abort_multipart_upload" {
  test_abort_multipart_upload_aws_root
}

# complete-multipart-upload
@test "test_complete_multipart_upload" {
  test_complete_multipart_upload_aws_root
}

# copy-object
@test "test_copy_object" {
  test_common_copy_object "s3api"
}

@test "test_copy_object_empty" {
  copy_object_empty || fail "copy objects with no parameters test failure"
}

# create-bucket
@test "test_create_delete_bucket_aws" {
  test_common_create_delete_bucket "aws"
}

@test "test_create_bucket_invalid_name" {
  test_create_bucket_invalid_name_aws_root
}

# create-multipart-upload
@test "test_create_multipart_upload_properties" {
  test_create_multipart_upload_properties_aws_root
}

# delete-bucket - test_create_delete_bucket_aws

# delete-bucket-policy
@test "test_get_put_delete_bucket_policy" {
  if [[ -n $SKIP_POLICY ]]; then
    skip "will not test policy actions with SKIP_POLICY set"
  fi
  test_common_get_put_delete_bucket_policy "aws"
}

# delete-bucket-tagging
@test "test-set-get-delete-bucket-tags" {
  test_common_set_get_delete_bucket_tags "aws"
}

# delete-object - tested with bucket cleanup before or after tests

# delete-object-tagging
@test "test_delete_object_tagging" {
  test_common_delete_object_tagging "aws"
}

# delete-objects
@test "test_delete_objects" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "https://github.com/versity/versitygw/issues/888"
  fi
  test_delete_objects_aws_root
}

# get-bucket-acl
@test "test_get_bucket_acl" {
  test_get_bucket_acl_aws_root
}

# get-bucket-location
@test "test_get_bucket_location" {
  test_common_get_bucket_location "aws"
}

# get-bucket-policy - test_get_put_delete_bucket_policy

# get-bucket-tagging - test_set_get_delete_bucket_tags

# get-object
@test "test_get_object_full_range" {
  test_get_object_full_range_aws_root
}

@test "test_get_object_invalid_range" {
  test_get_object_invalid_range_aws_root
}

# get-object-attributes
@test "test_get_object_attributes" {
  test_get_object_attributes_aws_root
}

@test "test_head_bucket_invalid_name" {
  if head_bucket "aws" ""; then
    fail "able to get bucket info for invalid name"
  fi
}

@test "test_put_object" {
  test_put_object_aws_root
}

# test adding and removing an object on versitygw
@test "test_put_object_with_data" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "https://github.com/versity/versitygw/issues/888"
  fi
  test_common_put_object_with_data "aws"
}

@test "test_put_object_no_data" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "https://github.com/versity/versitygw/issues/888"
  fi
  test_common_put_object_no_data "aws"
}

# test listing buckets on versitygw
@test "test_list_buckets" {
  test_common_list_buckets "s3api"
}

# test listing a bucket's objects on versitygw
@test "test_list_objects" {
  test_common_list_objects "aws"
}

@test "test_get_put_object_legal_hold" {
  test_get_put_object_legal_hold_aws_root
}

@test "test_get_put_object_retention" {
  test_get_put_object_retention_aws_root
}

@test "test_put_bucket_acl" {
  test_common_put_bucket_acl "s3api"
}

# test v1 s3api list objects command
@test "test-s3api-list-objects-v1" {
  test_s3api_list_objects_v1_aws_root
}

# test v2 s3api list objects command
@test "test-s3api-list-objects-v2" {
  test_s3api_list_objects_v2_aws_root
}

# test abilty to set and retrieve object tags
@test "test-set-get-object-tags" {
  test_common_set_get_object_tags "aws"
}

# test multi-part upload list parts command
@test "test-multipart-upload-list-parts" {
  test_multipart_upload_list_parts_aws_root
}

# test listing of active uploads
@test "test-multipart-upload-list-uploads" {
  local bucket_file_one="bucket-file-one"
  local bucket_file_two="bucket-file-two"

  if [[ $RECREATE_BUCKETS == false ]]; then
    run abort_all_multipart_uploads "$BUCKET_ONE_NAME"
    assert_success
  fi

  run create_test_files "$bucket_file_one" "$bucket_file_two"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  run create_list_check_multipart_uploads "$BUCKET_ONE_NAME" "$bucket_file_one" "$bucket_file_two"
  assert_success
}

@test "test-multipart-upload-from-bucket" {
  local bucket_file="bucket-file"

  run create_test_file "$bucket_file"
  assert_success

  run dd if=/dev/urandom of="$TEST_FILE_FOLDER/$bucket_file" bs=5M count=1
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  run multipart_upload_from_bucket "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER"/"$bucket_file" 4
  assert_success

  run get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file-copy" "$TEST_FILE_FOLDER/$bucket_file-copy"
  assert_success

  run compare_files "$TEST_FILE_FOLDER"/$bucket_file-copy "$TEST_FILE_FOLDER"/$bucket_file
  assert_success
}

@test "test_multipart_upload_from_bucket_range_too_large" {
  local bucket_file="bucket-file"
  run create_large_file "$bucket_file"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  run multipart_upload_range_too_large "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER"/"$bucket_file"
  assert_success
}

@test "test_multipart_upload_from_bucket_range_valid" {
  local bucket_file="bucket-file"
  run create_large_file "$bucket_file"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  range_max=$((5*1024*1024-1))
  multipart_upload_from_bucket_range "$BUCKET_ONE_NAME" "$bucket_file" "$TEST_FILE_FOLDER"/"$bucket_file" 4 "bytes=0-$range_max" || fail "upload failure"

  get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file-copy" "$TEST_FILE_FOLDER/$bucket_file-copy" || fail "error retrieving object after upload"
  if [[ $(uname) == 'Darwin' ]]; then
    object_size=$(stat -f%z "$TEST_FILE_FOLDER/$bucket_file-copy")
  else
    object_size=$(stat --format=%s "$TEST_FILE_FOLDER/$bucket_file-copy")
  fi
  [[ object_size -eq $((range_max*4+4)) ]] || fail "object size mismatch ($object_size, $((range_max*4+4)))"

  bucket_cleanup "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

@test "test-presigned-url-utf8-chars" {
  test_common_presigned_url_utf8_chars "aws"
}

@test "test-list-objects-delimiter" {
  folder_name="two"
  object_name="three"

  run create_test_folder "$folder_name"
  assert_success

  run create_test_file "$folder_name"/"$object_name"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  put_object "aws" "$TEST_FILE_FOLDER/$folder_name/$object_name" "$BUCKET_ONE_NAME" "$folder_name/$object_name" || fail "failed to add object to bucket"

  list_objects_s3api_v1 "$BUCKET_ONE_NAME" "/"
  prefix=$(echo "${objects[@]}" | jq -r ".CommonPrefixes[0].Prefix" 2>&1) || fail "error getting object prefix from object list: $prefix"
  [[ $prefix == "$folder_name/" ]] || fail "prefix doesn't match (expected $prefix, actual $folder_name/)"

  list_objects_s3api_v1 "$BUCKET_ONE_NAME" "#"
  key=$(echo "${objects[@]}" | jq -r ".Contents[0].Key" 2>&1) || fail "error getting key from object list: $key"
  [[ $key == "$folder_name/$object_name" ]] || fail "key doesn't match (expected $key, actual $folder_name/$object_name)"

  bucket_cleanup "aws" "$BUCKET_ONE_NAME"
  delete_test_files $folder_name
}

# ensure that lists of files greater than a size of 1000 (pagination) are returned properly
#@test "test_list_objects_file_count" {
#  test_common_list_objects_file_count "aws"
#}

# ensure that lists of files greater than a size of 1000 (pagination) are returned properly
#@test "test_list_objects_file_count" {
#  test_common_list_objects_file_count "aws"
#}

#@test "test_filename_length" {
#  file_name=$(printf "%0.sa" $(seq 1 1025))
#  echo "$file_name"

#  create_test_files "$file_name" || created=$?
#  [[ $created -eq 0 ]] || fail "error creating file"

#  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
#  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

#  put_object "aws" "$TEST_FILE_FOLDER"/"$file_name" "$BUCKET_ONE_NAME"/"$file_name" || local put_object=$?
#  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket"
#}

@test "test_head_bucket" {
  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  head_bucket "aws" "$BUCKET_ONE_NAME" || fail "error getting bucket info"
  log 5 "INFO:  $bucket_info"
  region=$(echo "$bucket_info" | grep -v "InsecureRequestWarning" | jq -r ".BucketRegion" 2>&1) || fail "error getting bucket region: $region"
  [[ $region != "" ]] || fail "empty bucket region"
  bucket_cleanup "aws" "$BUCKET_ONE_NAME"
}

@test "test_retention_bypass" {
  test_retention_bypass_aws_root
}

@test "test_head_bucket_doesnt_exist" {
  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  head_bucket "aws" "$BUCKET_ONE_NAME"a || local info_result=$?
  [[ $info_result -eq 1 ]] || fail "bucket info for non-existent bucket returned"
  [[ $bucket_info == *"404"* ]] || fail "404 not returned for non-existent bucket info"
  bucket_cleanup "aws" "$BUCKET_ONE_NAME"
}

@test "test_add_object_metadata" {
  object_one="object-one"
  test_key="x-test-data"
  test_value="test-value"

  run create_test_files "$object_one"
  assert_success

  run setup_bucket "aws" "$BUCKET_ONE_NAME"
  assert_success

  object="$TEST_FILE_FOLDER"/"$object_one"
  put_object_with_metadata "aws" "$object" "$BUCKET_ONE_NAME" "$object_one" "$test_key" "$test_value" || fail "failed to add object to bucket"
  object_exists "aws" "$BUCKET_ONE_NAME" "$object_one" || fail "object not found after being added to bucket"

  get_object_metadata "aws" "$BUCKET_ONE_NAME" "$object_one" || fail "error getting object metadata"
  key=$(echo "$metadata" | jq -r 'keys[]' 2>&1) || fail "error getting key from metadata: $key"
  value=$(echo "$metadata" | jq -r '.[]' 2>&1) || fail "error getting value from metadata: $value"
  [[ $key == "$test_key" ]] || fail "keys doesn't match (expected $key, actual \"$test_key\")"
  [[ $value == "$test_value" ]] || fail "values doesn't match (expected $value, actual \"$test_value\")"

  bucket_cleanup "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one"
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

  bucket_cleanup "aws" "$bucket_name"
}

@test "test_ls_directory_object" {
  test_common_ls_directory_object "s3api"
}

