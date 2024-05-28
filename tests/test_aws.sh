#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_aws.sh
source ./tests/util_bucket_create.sh
source ./tests/util_file.sh
source ./tests/util_users.sh
source ./tests/test_common.sh
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
source ./tests/commands/put_object_retention.sh
source ./tests/commands/select_object_content.sh

# abort-multipart-upload
@test "test_abort_multipart_upload" {
  local bucket_file="bucket-file"
  bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  run_then_abort_multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || abort_result=$?
  [[ $abort_result -eq 0 ]] || fail "Abort failed"

  object_exists "aws" "$BUCKET_ONE_NAME" "$bucket_file" || exists=$?
  [[ $exists -eq 1 ]] || fail "Upload file exists after abort"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

# complete-multipart-upload
@test "test_complete_multipart_upload" {
  local bucket_file="bucket-file"
  bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || upload_result=$?
  [[ $upload_result -eq 0 ]] || fail "Error performing multipart upload"

  copy_file "s3://$BUCKET_ONE_NAME/$bucket_file" "$test_file_folder/$bucket_file-copy"
  compare_files "$test_file_folder/$bucket_file-copy" "$test_file_folder"/$bucket_file || compare_result=$?
  [[ $compare_result -eq 0 ]] || fail "Files do not match"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

# copy-object
@test "test_copy_object" {
  test_common_copy_object "s3api"
}

@test "test_copy_object_empty" {
  copy_object_empty || local result=$?
  [[ result -eq 0 ]] || fail "copy objects with no parameters test failure"
}

# create-bucket
@test "test_create_delete_bucket_aws" {
  test_common_create_delete_bucket "aws"
}

# create-multipart-upload
@test "test_create_multipart_upload_properties" {
  local bucket_file="bucket-file"
  local bucket_file_data="test file\n"

  local expected_content_type="application/zip"
  local expected_meta_key="testKey"
  local expected_meta_val="testValue"
  local expected_hold_status="ON"
  local expected_retention_mode="GOVERNANCE"
  local expected_tag_key="TestTag"
  local expected_tag_val="TestTagVal"
  local five_seconds_later

  os_name="$(uname)"
  if [[ "$os_name" == "Darwin" ]]; then
    now=$(date -u +"%Y-%m-%dT%H:%M:%S")
    five_seconds_later=$(date -j -v +5S -f "%Y-%m-%dT%H:%M:%S" "$now" +"%Y-%m-%dT%H:%M:%S")
  else
    now=$(date +"%Y-%m-%dT%H:%M:%S")
    five_seconds_later=$(date -d "$now 5 seconds" +"%Y-%m-%dT%H:%M:%S")
  fi

  create_test_files "$bucket_file" || fail "error creating test file"
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file

  delete_bucket_if_exists "s3api" "$BUCKET_ONE_NAME" || fail "error deleting bucket, or checking for existence"
  create_bucket_object_lock_enabled "$BUCKET_ONE_NAME" || fail "error creating bucket"

  log 5 "$five_seconds_later"
  multipart_upload_with_params "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 \
    "$expected_content_type" \
    "{\"$expected_meta_key\": \"$expected_meta_val\"}" \
    "$expected_hold_status" \
    "$expected_retention_mode" \
    "$five_seconds_later" \
    "$expected_tag_key=$expected_tag_val" || fail "error performing multipart upload"

  head_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting metadata"
  raw_metadata=$(echo "$metadata" | grep -v "InsecureRequestWarning")
  log 5 "raw metadata: $raw_metadata"

  content_type=$(echo "$raw_metadata" | jq -r ".ContentType")
  [[ $content_type == "$expected_content_type" ]] || fail "content type mismatch ($content_type, $expected_content_type)"
  meta_val=$(echo "$raw_metadata" | jq -r ".Metadata.$expected_meta_key")
  [[ $meta_val == "$expected_meta_val" ]] || fail "metadata val mismatch ($meta_val, $expected_meta_val)"
  hold_status=$(echo "$raw_metadata" | jq -r ".ObjectLockLegalHoldStatus")
  [[ $hold_status == "$expected_hold_status" ]] || fail "hold status mismatch ($hold_status, $expected_hold_status)"
  retention_mode=$(echo "$raw_metadata" | jq -r ".ObjectLockMode")
  [[ $retention_mode == "$expected_retention_mode" ]] || fail "retention mode mismatch ($retention_mode, $expected_retention_mode)"
  retain_until_date=$(echo "$raw_metadata" | jq -r ".ObjectLockRetainUntilDate")
  [[ $retain_until_date == "$five_seconds_later"* ]] || fail "retention date mismatch ($retain_until_date, $five_seconds_later)"

  get_object_tagging "aws" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting tagging"
  log 5 "tags: $tags"
  tag_key=$(echo "$tags" | jq -r ".TagSet[0].Key")
  [[ $tag_key == "$expected_tag_key" ]] || fail "tag mismatch ($tag_key, $expected_tag_key)"
  tag_val=$(echo "$tags" | jq -r ".TagSet[0].Value")
  [[ $tag_val == "$expected_tag_val" ]] || fail "tag mismatch ($tag_val, $expected_tag_val)"

  put_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" "OFF" || fail "error disabling legal hold"
  head_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting metadata"

  get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder/$bucket_file-copy" || fail "error getting object"
  compare_files "$test_file_folder/$bucket_file" "$test_file_folder/$bucket_file-copy" || fail "files not equal"

  sleep 2

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}


# delete-bucket - test_create_delete_bucket_aws

# delete-bucket-policy
@test "test_get_put_delete_bucket_policy" {
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
  local object_one="test-file-one"
  local object_two="test-file-two"

  create_test_files "$object_one" "$object_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result_one=$?
  [[ $result_one -eq 0 ]] || fail "Error creating bucket"

  put_object "s3api" "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME" "$object_one" || local result_two=$?
  [[ $result_two -eq 0 ]] || fail "Error adding object one"
  put_object "s3api" "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME" "$object_two" || local result_three=$?
  [[ $result_three -eq 0 ]] || fail "Error adding object two"

  error=$(aws --no-verify-ssl s3api delete-objects --bucket "$BUCKET_ONE_NAME" --delete '{
    "Objects": [
      {"Key": "test-file-one"},
      {"Key": "test-file-two"}
    ]
  }') || local result=$?
  [[ $result -eq 0 ]] || fail "Error deleting objects: $error"

  object_exists "aws" "$BUCKET_ONE_NAME" "$object_one" || local exists_one=$?
  [[ $exists_one -eq 1 ]] || fail "Object one not deleted"
  object_exists "aws" "$BUCKET_ONE_NAME" "$object_two" || local exists_two=$?
  [[ $exists_two -eq 1 ]] || fail "Object two not deleted"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

# get-bucket-acl
@test "test_get_bucket_acl" {
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"

  get_bucket_acl "s3api" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"

  id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq '.Owner.ID')
  [[ $id == '"'"$AWS_ACCESS_KEY_ID"'"' ]] || fail "Acl mismatch"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

#@test "test_get_object_invalid_range" {
#  bucket_file="bucket_file"
#
#  create_test_files "$bucket_file" || local created=$?
#  [[ $created -eq 0 ]] || fail "Error creating test files"
#  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local setup_result=$?
#  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
#  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error putting object"
#  get_object_with_range "$BUCKET_ONE_NAME" "$bucket_file" "bytes=0-0" "$test_file_folder/$bucket_file-range" || local get_result=$?
#  [[ $get_result -ne 0 ]] || fail "Get object with zero range returned no error"
#}

#@test "test_get_object_full_range" {
#  bucket_file="bucket_file"
#
#  create_test_files "$bucket_file" || local created=$?
#  [[ $created -eq 0 ]] || fail "Error creating test files"
#  echo -n "0123456789" > "$test_file_folder/$bucket_file"
#  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local setup_result=$?
#  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
#  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error putting object"
#  get_object_with_range "$BUCKET_ONE_NAME" "$bucket_file" "bytes=9-15" "$test_file_folder/$bucket_file-range" || fail "error getting range"
#  cat "$test_file_folder/$bucket_file"
#  cat "$test_file_folder/$bucket_file-range"
#  ls -l "$test_file_folder/$bucket_file"
#  ls -l "$test_file_folder/$bucket_file-range"
#  compare_files "$test_file_folder/$bucket_file" "$test_file_folder/$bucket_file-range" || fail "files not equal"
#}

@test "test_put_object" {
  bucket_file="bucket_file"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  setup_bucket "s3api" "$BUCKET_TWO_NAME" || local setup_result_two=$?
  [[ $setup_result_two -eq 0 ]] || fail "Bucket two setup error"
  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"
  copy_error=$(aws --no-verify-ssl s3api copy-object --copy-source "$BUCKET_ONE_NAME/$bucket_file" --key "$bucket_file" --bucket "$BUCKET_TWO_NAME" 2>&1) || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Error copying file: $copy_error"
  copy_file "s3://$BUCKET_TWO_NAME/$bucket_file" "$test_file_folder/${bucket_file}_copy" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"
  compare_files "$test_file_folder/$bucket_file" "$test_file_folder/${bucket_file}_copy" || local compare_result=$?
  [[ $compare_result -eq 0 ]] || file "files don't match"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_bucket_or_contents "aws" "$BUCKET_TWO_NAME"
  delete_test_files "$bucket_file"
}

@test "test_create_bucket_invalid_name" {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  create_bucket_invalid_name "aws" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Invalid name test failed"

  [[ "$bucket_create_error" == *"Invalid bucket name "* ]] || fail "unexpected error:  $bucket_create_error"
}

# test adding and removing an object on versitygw
@test "test_put_object_with_data" {
  test_common_put_object_with_data "aws"
}

@test "test_put_object_no_data" {
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


@test "test_get_object_attributes" {
  bucket_file="bucket_file"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"
  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"
  get_object_attributes "$BUCKET_ONE_NAME" "$bucket_file" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "failed to get object attributes"
  # shellcheck disable=SC2154
  if echo "$attributes" | jq -e 'has("ObjectSize")'; then
    object_size=$(echo "$attributes" | jq ".ObjectSize")
    [[ $object_size == 0 ]] || fail "Incorrect object size: $object_size"
  else
    fail "ObjectSize parameter missing: $attributes"
  fi
  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
}

@test "test_get_put_object_legal_hold" {
  # bucket must be created with lock for legal hold
  if [[ $RECREATE_BUCKETS == false ]]; then
    return
  fi

  bucket_file="bucket_file"
  username="ABCDEFG"
  secret_key="HIJKLMN"

  legal_hold_retention_setup "$username" "$secret_key" "$bucket_file"

  get_object_lock_configuration "$BUCKET_ONE_NAME" || fail "error getting lock configuration"
  # shellcheck disable=SC2154
  log 5 "$lock_config"
  enabled=$(echo "$lock_config" | jq -r ".ObjectLockConfiguration.ObjectLockEnabled")
  [[ $enabled == "Enabled" ]] || fail "ObjectLockEnabled should be 'Enabled', is '$enabled'"

  put_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" "ON" || fail "error putting legal hold on object"
  get_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting object legal hold status"
  # shellcheck disable=SC2154
  log 5 "$legal_hold"
  hold_status=$(echo "$legal_hold" | grep -v "InsecureRequestWarning" | jq -r ".LegalHold.Status")
  [[ $hold_status == "ON" ]] || fail "Status should be 'ON', is '$hold_status'"

  echo "fdkljafajkfs" > "$test_file_folder/$bucket_file"
  put_object_with_user "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key" || local put_result=$?
  [[ $put_result -ne 0 ]] || fail "able to overwrite object with hold"
  # shellcheck disable=SC2154
  [[ $put_object_error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $put_object_error"

  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key" || local delete_result=$?
  [[ $delete_result -ne 0 ]] || fail "able to delete object with hold"
  # shellcheck disable=SC2154
  [[ $delete_object_error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $delete_object_error"
  put_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" "OFF" || fail "error removing legal hold on object"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key" || fail "error deleting object after removing legal hold"

  delete_bucket_recursive "s3api" "$BUCKET_ONE_NAME"
}

#@test "test_get_put_object_retention" {
#  # bucket must be created with lock for legal hold
#  if [[ $RECREATE_BUCKETS == false ]]; then
#    return
#  fi
#
#  bucket_file="bucket_file"
#  username="ABCDEFG"
#  secret_key="HIJKLMN"
#
#  legal_hold_retention_setup "$username" "$secret_key" "$bucket_file"
#
#  get_object_lock_configuration "$BUCKET_ONE_NAME" || fail "error getting lock configuration"
#  log 5 "$lock_config"
#  enabled=$(echo "$lock_config" | jq -r ".ObjectLockConfiguration.ObjectLockEnabled")
#  [[ $enabled == "Enabled" ]] || fail "ObjectLockEnabled should be 'Enabled', is '$enabled'"
#
#  if [[ "$OSTYPE" == "darwin"* ]]; then
#    retention_date=$(date -v+2d +"%Y-%m-%dT%H:%M:%S")
#  else
#    retention_date=$(date -d "+2 days" +"%Y-%m-%dT%H:%M:%S")
#  fi
#  put_object_retention "$BUCKET_ONE_NAME" "$bucket_file" "GOVERNANCE" "$retention_date" || fail "failed to add object retention"
#  get_object_retention "$BUCKET_ONE_NAME" "$bucket_file" || fail "failed to get object retention"
#  log 5 "$retention"
#  retention=$(echo "$retention" | grep -v "InsecureRequestWarning")
#  mode=$(echo "$retention" | jq -r ".Retention.Mode")
#  retain_until_date=$(echo "$retention" | jq -r ".Retention.RetainUntilDate")
#  [[ $mode == "GOVERNANCE" ]] || fail "retention mode should be governance, is $mode"
#  [[ $retain_until_date == "$retention_date"* ]] || fail "retain until date should be $retention_date, is $retain_until_date"
#
#  echo "fdkljafajkfs" > "$test_file_folder/$bucket_file"
#  put_object_with_user "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key" || local put_result=$?
#  [[ $put_result -ne 0 ]] || fail "able to overwrite object with hold"
#  [[ $error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $error"
#
#  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key" || local delete_result=$?
#  [[ $delete_result -ne 0 ]] || fail "able to delete object with hold"
#  [[ $error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $error"
#
#  delete_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error deleting object"
#  delete_bucket_recursive "s3api" "$BUCKET_ONE_NAME"
#}

legal_hold_retention_setup() {
  if [[ $# -ne 3 ]]; then
    log 2 "legal hold or retention setup requires username, secret key, bucket file"
    return 1
  fi

  delete_bucket_if_exists "s3api" "$BUCKET_ONE_NAME" || fail "error deleting bucket, or checking for existence"
  create_user_if_nonexistent "$1" "$2" "user" || fail "error creating user if nonexistent"
  create_test_files "$3" || fail "error creating test files"

  create_bucket_object_lock_enabled "$BUCKET_ONE_NAME" || fail "error creating bucket"
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$1" || fail "error changing bucket ownership"
  put_object_with_user "s3api" "$test_file_folder/$3" "$BUCKET_ONE_NAME" "$3" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" || fail "failed to add object to bucket"
}

@test "test_put_bucket_acl" {
  test_common_put_bucket_acl "s3api"
}

# test ability to retrieve object ACLs
#@test "test_get_object_acl" {

#  object_one="test-file-one"

#  setup_bucket "$BUCKET_ONE_NAME" || local created=$?
#  [[ $created -eq 0 ]] || fail "Error creating bucket"
#  create_test_files "$object_one" || local created=$?
#  [[ $created -eq 0 ]] || fail "Error creating test file"
#  put_object "$test_file_folder"/$object_one "$BUCKET_ONE_NAME"/"$object_one"  || local result=$?
#  [[ result -eq 0 ]] || fail "Error adding object one"

#  get_object_acl "$BUCKET_ONE_NAME" "$object_one" || local result=$?
#  [[ $result -eq 0 ]] || fail "Error retrieving acl"

#  id=$(echo "$acl" | jq '.Owner.ID')
#  [[ $id == '"'"$AWS_ACCESS_KEY_ID"'"' ]] || fail "Acl mismatch"

#  delete_bucket_or_contents "$BUCKET_ONE_NAME"
#}


#@test "test_select_object_content" {
#  bucket_file="bucket_file"
#
#  create_test_files "$bucket_file" || local created=$?
#  [[ $created -eq 0 ]] || fail "Error creating test files"
#
#  printf "Field,Value\nSomething,Also Something" > "$test_file_folder/$bucket_file"
#  cat "$test_file_folder/$bucket_file"
#
#  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local created=$?
#  [[ $created -eq 0 ]] || fail "Error creating bucket"
#  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || local copy_result=$?
#  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"
#  select_object_content "$BUCKET_ONE_NAME" "$bucket_file" "select * from s3object limit 1" "SQL" "{\"CSV\": {}}" "{\"CSV\": {}}" "output.csv"
#}

#@test "test_get_set_versioning" {
#  test_common_get_set_versioning "s3api"
#}

# test v1 s3api list objects command
@test "test-s3api-list-objects-v1" {
  local object_one="test-file-one"
  local object_two="test-file-two"
  local object_two_data="test data\n"

  create_test_files "$object_one" "$object_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  printf "%s" "$object_two_data" > "$test_file_folder"/"$object_two"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  put_object "s3api" "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME" "$object_one" || local copy_result_one=$?
  [[ $copy_result_one -eq 0 ]] || fail "Failed to add object $object_one"
  put_object "s3api" "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME" "$object_two" || local copy_result_two=$?
  [[ $copy_result_two -eq 0 ]] || fail "Failed to add object $object_two"

  sleep 1

  list_objects_s3api_v1 "$BUCKET_ONE_NAME"
  key_one=$(echo "$objects" | jq -r '.Contents[0].Key')
  [[ $key_one == "$object_one" ]] || fail "Object one mismatch ($key_one, $object_one)"
  size_one=$(echo "$objects" | jq -r '.Contents[0].Size')
  [[ $size_one -eq 0 ]] || fail "Object one size mismatch ($size_one, 0)"
  key_two=$(echo "$objects" | jq -r '.Contents[1].Key')
  [[ $key_two == "$object_two" ]] || fail "Object two mismatch ($key_two, $object_two)"
  size_two=$(echo "$objects" | jq '.Contents[1].Size')
  [[ $size_two -eq ${#object_two_data} ]] || fail "Object two size mismatch ($size_two, ${#object_two_data})"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

# test v2 s3api list objects command
@test "test-s3api-list-objects-v2" {
  local object_one="test-file-one"
  local object_two="test-file-two"
  local object_two_data="test data\n"

  create_test_files "$object_one" "$object_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  printf "%s" "$object_two_data" > "$test_file_folder"/"$object_two"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  put_object "s3api" "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME" "$object_one" || local copy_object_one=$?
  [[ $copy_object_one -eq 0 ]] || fail "Failed to add object $object_one"
  put_object "s3api" "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME" "$object_two" || local copy_object_two=$?
  [[ $copy_object_two -eq 0 ]] || fail "Failed to add object $object_two"

  list_objects_s3api_v2 "$BUCKET_ONE_NAME"
  key_one=$(echo "$objects" | jq -r '.Contents[0].Key')
  [[ $key_one == "$object_one" ]] || fail "Object one mismatch ($key_one, $object_one)"
  size_one=$(echo "$objects" | jq -r '.Contents[0].Size')
  [[ $size_one -eq 0 ]] || fail "Object one size mismatch ($size_one, 0)"
  key_two=$(echo "$objects" | jq -r '.Contents[1].Key')
  [[ $key_two == "$object_two" ]] || fail "Object two mismatch ($key_two, $object_two)"
  size_two=$(echo "$objects" | jq -r '.Contents[1].Size')
  [[ $size_two -eq ${#object_two_data} ]] || fail "Object two size mismatch ($size_two, ${#object_two_data})"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

# test abilty to set and retrieve object tags
@test "test-set-get-object-tags" {
  test_common_set_get_object_tags "aws"
}

# test multi-part upload list parts command
@test "test-multipart-upload-list-parts" {
  local bucket_file="bucket-file"
  local bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  list_parts "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || list_result=$?
  [[ list_result -eq 0 ]] || fail "Listing multipart upload parts failed"

  declare -a parts_map
  for i in {0..3}; do
    local part_number
    local etag
    part_number=$(echo "$parts" | jq ".[$i].PartNumber")
    if [[ $part_number -eq "" ]]; then
      echo "error:  blank part number"
      return 1
    fi
    etag=$(echo "$parts" | jq ".[$i].ETag")
    if [[ $etag == "" ]]; then
      echo "error:  blank etag"
      return 1
    fi
    # shellcheck disable=SC2004
    parts_map[$part_number]=$etag
  done
  [[ ${#parts_map[@]} -ne 0 ]] || fail "error loading multipart upload parts to check"

  for i in {0..3}; do
    local part_number
    local etag
    part_number=$(echo "$listed_parts" | jq ".Parts[$i].PartNumber")
    etag=$(echo "$listed_parts" | jq ".Parts[$i].ETag")
    if [[ ${parts_map[$part_number]} != "$etag" ]]; then
      echo "error:  etags don't match (part number: $part_number, etags ${parts_map[$part_number]},$etag)"
      return 1
    fi
  done

  run_then_abort_multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder/$bucket_file" 4
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

# test listing of active uploads
@test "test-multipart-upload-list-uploads" {
  local bucket_file_one="bucket-file-one"
  local bucket_file_two="bucket-file-two"

  if [[ $RECREATE_BUCKETS == false ]]; then
    abort_all_multipart_uploads "$BUCKET_ONE_NAME" || local abort_result=$?
    [[ $abort_result -eq 0 ]] || fail "error aborting all uploads"
  fi

  create_test_files "$bucket_file_one" "$bucket_file_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  list_multipart_uploads "$BUCKET_ONE_NAME" "$test_file_folder"/"$bucket_file_one" "$test_file_folder"/"$bucket_file_two" || fail "failed to list multipart uploads"

  local key_one
  local key_two
  log 5 "$uploads"
  key_one=$(echo "$uploads" | jq '.Uploads[0].Key')
  key_two=$(echo "$uploads" | jq '.Uploads[1].Key')
  key_one=${key_one//\"/}
  key_two=${key_two//\"/}
  if [[ "$test_file_folder/$bucket_file_one" != *"$key_one" ]]; then
    fail "Key mismatch ($test_file_folder/$bucket_file_one, $key_one)"
  fi
  if [[ "$test_file_folder/$bucket_file_two" != *"$key_two" ]]; then
    fail "Key mismatch ($test_file_folder/$bucket_file_two, $key_two)"
  fi

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$bucket_file_one" "$bucket_file_two"
}

@test "test-multipart-upload-from-bucket" {
  local bucket_file="bucket-file"
  bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  multipart_upload_from_bucket "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || upload_result=$?
  [[ $upload_result -eq 0 ]] || fail "Error performing multipart upload"

  get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file-copy" "$test_file_folder/$bucket_file-copy"
  compare_files "$test_file_folder"/$bucket_file-copy "$test_file_folder"/$bucket_file || compare_result=$?
  [[ $compare_result -eq 0 ]] || fail "Data doesn't match"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

#@test "test_multipart_upload_from_bucket_range" {
#  local bucket_file="bucket-file"
#
#  create_large_file "$bucket_file" || error creating file "$bucket_file"
#  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
#
#  multipart_upload_from_bucket_range "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 "bytes=0-1000000000" || local upload_result=$?
#  [[ $upload_result -eq 1 ]] || fail "multipart upload with overly large range should have failed"
#  [[ $upload_part_copy_error == *"Range specified is not valid"* ]] || fail "unexpected error: $upload_part_copy_error"
#
#  multipart_upload_from_bucket_range "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 "bytes=0-16000000" || local upload_two_result=$?
#  [[ $upload_two_result -eq 0 ]] || fail "range should be valid"
#
#  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
#  delete_test_files $bucket_file
#}

@test "test-presigned-url-utf8-chars" {
  test_common_presigned_url_utf8_chars "aws"
}

@test "test-list-objects-delimiter" {
  folder_name="two"
  object_name="three"
  create_test_folder "$folder_name" || local created=$?
  [[ $created -eq 0 ]] || fail "error creating folder"
  create_test_files "$folder_name"/"$object_name" || created=$?
  [[ $created -eq 0 ]] || fail "error creating file"

  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  put_object "aws" "$test_file_folder/$folder_name/$object_name" "$BUCKET_ONE_NAME" "$folder_name/$object_name" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"

  list_objects_s3api_v1 "$BUCKET_ONE_NAME" "/"
  prefix=$(echo "${objects[@]}" | jq ".CommonPrefixes[0].Prefix")
  [[ $prefix == "\""$folder_name/"\"" ]] || fail "prefix doesn't match (expected $prefix, actual $folder_name/)"

  list_objects_s3api_v1 "$BUCKET_ONE_NAME" "#"
  key=$(echo "${objects[@]}" | jq ".Contents[0].Key")
  [[ $key == "\""$folder_name/$object_name"\"" ]] || fail "prefix doesn't match (expected $prefix, actual $folder_name/)"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $folder_name
}

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

#  put_object "aws" "$test_file_folder"/"$file_name" "$BUCKET_ONE_NAME"/"$file_name" || local put_object=$?
#  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket"
#}

@test "test_head_bucket" {
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  head_bucket "aws" "$BUCKET_ONE_NAME"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

@test "test_head_bucket_invalid_name" {
  head_bucket "aws" "" || local head_result=$?
  [[ $head_result -ne 0 ]] || fail "able to get bucket info for invalid name"
}

@test "test_head_bucket_doesnt_exist" {
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  head_bucket "aws" "$BUCKET_ONE_NAME"a || local info_result=$?
  [[ $info_result -eq 1 ]] || fail "bucket info for non-existent bucket returned"
  [[ $bucket_info == *"404"* ]] || fail "404 not returned for non-existent bucket info"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

@test "test_add_object_metadata" {

  object_one="object-one"
  test_key="x-test-data"
  test_value="test-value"

  create_test_files "$object_one" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"

  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  object="$test_file_folder"/"$object_one"
  put_object_with_metadata "aws" "$object" "$BUCKET_ONE_NAME" "$object_one" "$test_key" "$test_value" || copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"
  object_exists "aws" "$BUCKET_ONE_NAME" "$object_one" || local exists_result_one=$?
  [[ $exists_result_one -eq 0 ]] || fail "Object not added to bucket"

  get_object_metadata "aws" "$BUCKET_ONE_NAME" "$object_one" || get_result=$?
  [[ $get_result -eq 0 ]] || fail "error getting object metadata"
  key=$(echo "$metadata" | jq 'keys[]')
  value=$(echo "$metadata" | jq '.[]')
  [[ $key == "\"$test_key\"" ]] || fail "keys doesn't match (expected $key, actual \"$test_key\")"
  [[ $value == "\"$test_value\"" ]] || fail "values doesn't match (expected $value, actual \"$test_value\")"
}


@test "test_get_bucket_location" {
  test_common_get_bucket_location "aws"
}
