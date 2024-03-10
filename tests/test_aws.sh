#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_file.sh
source ./tests/test_common.sh

# test creation and deletion of bucket on versitygw
@test "test_create_delete_bucket_aws" {
  test_common_create_delete_bucket "aws"
}

# test adding and removing an object on versitygw
@test "test_put_object-with-data" {
  test_common_put_object_with_data "aws"
}

@test "test_put_object-no-data" {
  test_common_put_object_no_data "aws"
}

# test listing buckets on versitygw
@test "test_list_buckets" {
  test_common_list_buckets "aws"
}

# test listing a bucket's objects on versitygw
@test "test_list_objects" {
  test_common_list_objects "aws"
}

# test ability to retrieve bucket ACLs
@test "test_get_bucket_acl" {

  setup_bucket "aws" "$BUCKET_ONE_NAME" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"

  get_bucket_acl "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"

  id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq '.Owner.ID')
  [[ $id == '"'"$AWS_ACCESS_KEY_ID"'"' ]] || fail "Acl mismatch"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
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


# test ability to delete multiple objects from bucket
@test "test_delete_objects" {

  local object_one="test-file-one"
  local object_two="test-file-two"

  create_test_files "$object_one" "$object_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result_one=$?
  [[ $result_one -eq 0 ]] || fail "Error creating bucket"

  put_object "aws" "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME"/"$object_one"  || local result_two=$?
  [[ $result_two -eq 0 ]] || fail "Error adding object one"
  put_object "aws" "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME"/"$object_two" || local result_three=$?
  [[ $result_three -eq 0 ]] || fail "Error adding object two"

  error=$(aws --no-verify-ssl s3api delete-objects --bucket "$BUCKET_ONE_NAME" --delete '{
    "Objects": [
      {"Key": "test-file-one"},
      {"Key": "test-file-two"}
    ]
  }') || local result=$?
  [[ $result -eq 0 ]] || fail "Error deleting objects: $error"

  object_exists "aws" "$BUCKET_ONE_NAME"/"$object_one" || local exists_one=$?
  [[ $exists_one -eq 1 ]] || fail "Object one not deleted"
  object_exists "aws" "$BUCKET_ONE_NAME"/"$object_two" || local exists_two=$?
  [[ $exists_two -eq 1 ]] || fail "Object two not deleted"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

# test abilty to set and retrieve bucket tags
@test "test-set-get-bucket-tags" {
  test_common_set_get_bucket_tags "aws"
}

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
  put_object "aws" "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME"/"$object_one" || local put_object_one=$?
  [[ $put_object_one -eq 0 ]] || fail "Failed to add object $object_one"
  put_object "aws" "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME"/"$object_two" || local put_object_two=$?
  [[ $put_object_two -eq 0 ]] || fail "Failed to add object $object_two"

  list_objects_s3api_v1 "$BUCKET_ONE_NAME"
  key_one=$(echo "$objects" | jq '.Contents[0].Key')
  [[ $key_one == '"'$object_one'"' ]] || fail "Object one mismatch"
  size_one=$(echo "$objects" | jq '.Contents[0].Size')
  [[ $size_one -eq 0 ]] || fail "Object one size mismatch"
  key_two=$(echo "$objects" | jq '.Contents[1].Key')
  [[ $key_two == '"'$object_two'"' ]] || fail "Object two mismatch"
  size_two=$(echo "$objects" | jq '.Contents[1].Size')
  [[ $size_two -eq ${#object_two_data} ]] || fail "Object two size mismatch"

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
  put_object "aws" "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME"/"$object_one" || local put_object_one=$?
  [[ $put_object_one -eq 0 ]] || fail "Failed to add object $object_one"
  put_object "aws" "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME"/"$object_two" || local put_object_two=$?
  [[ $put_object_two -eq 0 ]] || fail "Failed to add object $object_two"

  list_objects_s3api_v2 "$BUCKET_ONE_NAME"
  key_one=$(echo "$objects" | jq '.Contents[0].Key')
  [[ $key_one == '"'$object_one'"' ]] || fail "Object one mismatch"
  size_one=$(echo "$objects" | jq '.Contents[0].Size')
  [[ $size_one -eq 0 ]] || fail "Object one size mismatch"
  key_two=$(echo "$objects" | jq '.Contents[1].Key')
  [[ $key_two == '"'$object_two'"' ]] || fail "Object two mismatch"
  size_two=$(echo "$objects" | jq '.Contents[1].Size')
  [[ $size_two -eq ${#object_two_data} ]] || fail "Object two size mismatch"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

# test abilty to set and retrieve object tags
@test "test-set-get-object-tags" {
  test_common_set_get_object_tags "aws"
}

# test multi-part upload
@test "test-multi-part-upload" {

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

# test multi-part upload abort
@test "test-multi-part-upload-abort" {

  local bucket_file="bucket-file"
  bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  abort_multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || abort_result=$?
  [[ $abort_result -eq 0 ]] || fail "Abort failed"

  object_exists "aws" "$BUCKET_ONE_NAME/$bucket_file" || exists=$?
  [[ $exists -eq 1 ]] || fail "Upload file exists after abort"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
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
  for ((i=0;i<$4;i++)) {
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
    parts_map[$part_number]=$etag
  }

  for ((i=0;i<$4;i++)) {
    local part_number
    local etag
    part_number=$(echo "$listed_parts" | jq ".Parts[$i].PartNumber")
    etag=$(echo "$listed_parts" | jq ".Parts[$i].ETag")
    if [[ ${parts_map[$part_number]} != "$etag" ]]; then
      echo "error:  etags don't match (part number: $part_number, etags ${parts_map[$part_number]},$etag)"
      return 1
    fi
  }

  run_abort_command "$BUCKET_ONE_NAME" "$bucket_file" $upload_id
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

# test listing of active uploads
@test "test-multipart-upload-list-uploads" {

  local bucket_file_one="bucket-file-one"
  local bucket_file_two="bucket-file-two"

  create_test_files "$bucket_file_one" "$bucket_file_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  list_multipart_uploads "$BUCKET_ONE_NAME" "$test_file_folder"/"$bucket_file_one" "$test_file_folder"/"$bucket_file_two"
  [[ $? -eq 0 ]] || fail "failed to list multipart uploads"

  local key_one
  local key_two
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
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  multipart_upload_from_bucket "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || upload_result=$?
  [[ $upload_result -eq 0 ]] || fail "Error performing multipart upload"

  copy_file "s3://$BUCKET_ONE_NAME/$bucket_file-copy" "$test_file_folder/$bucket_file-copy"
  compare_files "$test_file_folder"/$bucket_file-copy "$test_file_folder"/$bucket_file || compare_result=$?
  [[ $compare_result -eq 0 ]] || fail "Data doesn't match"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}
