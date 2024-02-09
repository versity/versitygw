#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh

# test creation and deletion of bucket on versitygw
@test "test_create_delete_bucket" {

  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  setup_bucket "$BUCKET_ONE_NAME" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Failed to create bucket"
  bucket_exists "$BUCKET_ONE_NAME" || local exists_three=$?
  [[ $exists_three -eq 0 ]] || fail "Failed bucket existence check"
  delete_bucket_or_contents "$BUCKET_ONE_NAME" || local delete_result_two=$?
  [[ $delete_result_two -eq 0 ]] || fail "Failed to delete bucket"
}

# test adding and removing an object on versitygw
@test "test_put_object" {

  local object_name="test-object"

  setup_bucket "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  create_test_files "$object_name" || local create_result=$?

  object="$BUCKET_ONE_NAME"/$object_name
  put_object "$test_file_folder"/"$object_name" "$object" || local put_object=$?
  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket"
  object_exists "$object" || local exists_result_one=$?
  [[ $exists_result_one -eq 0 ]] || fail "Object not added to bucket"
  delete_object "$object" || local delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "Failed to delete object"
  object_exists "$object" || local exists_result_two=$?
  [[ $exists_result_two -eq 1 ]] || fail "Object not removed from bucket"
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_test_files "$object_name"
}

# test listing buckets on versitygw
@test "test_list_buckets" {

  setup_bucket "$BUCKET_ONE_NAME" || local setup_result_one=$?
  [[ $setup_result_one -eq 0 ]] || fail "Bucket one setup error"
  setup_bucket "$BUCKET_TWO_NAME" || local setup_result_two=$?
  [[ $setup_result_two -eq 0 ]] || fail "Bucket two setup error"
  list_buckets
  local bucket_one_found=false
  local bucket_two_found=false
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$BUCKET_ONE_NAME" ]; then
      bucket_one_found=true
    elif [ "$bucket" == "$BUCKET_TWO_NAME" ]; then
      bucket_two_found=true
    fi
    if [ $bucket_one_found == true ] && [ $bucket_two_found == true ]; then
      return
    fi
  done
  fail "'$BUCKET_ONE_NAME' and/or '$BUCKET_TWO_NAME' not listed (all buckets: ${bucket_array[*]})"
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_bucket_or_contents "$BUCKET_TWO_NAME"
}

# test listing a bucket's objects on versitygw
@test "test_list_objects" {

  object_one="test-file-one"
  object_two="test-file-two"

  create_test_files $object_one $object_two
  setup_bucket "$BUCKET_ONE_NAME" || local result_one=$?
  [[ result_one -eq 0 ]] || fail "Error creating bucket"
  put_object "$test_file_folder"/$object_one "$BUCKET_ONE_NAME"/"$object_one"  || local result_two=$?
  [[ result_two -eq 0 ]] || fail "Error adding object one"
  put_object "$test_file_folder"/$object_two "$BUCKET_ONE_NAME"/"$object_two" || local result_three=$?
  [[ result_three -eq 0 ]] || fail "Error adding object two"
  list_objects "$BUCKET_ONE_NAME"
  local object_one_found=false
  local object_two_found=false
  for object in "${object_array[@]}"; do
    if [ "$object" == $object_one ]; then
      object_one_found=true
    elif [ "$object" == $object_two ]; then
      object_two_found=true
    fi
  done
  if [ $object_one_found != true ] || [ $object_two_found != true ]; then
    fail "$object_one and/or $object_two not listed (all objects: ${object_array[*]})"
  fi
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_test_files $object_one $object_two
}

# test ability to retrieve bucket ACLs
@test "test_get_bucket_acl" {

  setup_bucket "$BUCKET_ONE_NAME" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"
  get_bucket_acl "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"
  id=$(echo "$acl" | jq '.Owner.ID')
  [[ $id == '"'"$AWS_ACCESS_KEY_ID"'"' ]] || fail "Acl mismatch"
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
}

# test ability to delete multiple objects from bucket
@test "test_delete_objects" {

  local object_one="test-file-one"
  local object_two="test-file-two"

  create_test_files "$object_one" "$object_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "$BUCKET_ONE_NAME" || local result_one=$?
  [[ $result_one -eq 0 ]] || fail "Error creating bucket"
  put_object "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME"/"$object_one"  || local result_two=$?
  [[ $result_two -eq 0 ]] || fail "Error adding object one"
  put_object "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME"/"$object_two" || local result_three=$?
  [[ $result_three -eq 0 ]] || fail "Error adding object two"

  error=$(aws s3api delete-objects --bucket "$BUCKET_ONE_NAME" --delete '{
    "Objects": [
      {"Key": "test-file-one"},
      {"Key": "test-file-two"}
    ]
  }') || local result=$?
  [[ $result -eq 0 ]] || fail "Error deleting objects: $error"

  object_exists "$BUCKET_ONE_NAME"/"$object_one" || local exists_one=$?
  [[ $exists_one -eq 1 ]] || fail "Object one not deleted"
  object_exists "$BUCKET_ONE_NAME"/"$object_two" || local exists_two=$?
  [[ $exists_two -eq 1 ]] || fail "Object two not deleted"

  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

# test abilty to set and retrieve bucket tags
@test "test-set-get-bucket-tags" {

  local key="test_key"
  local value="test_value"

  setup_bucket "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  get_bucket_tags "$BUCKET_ONE_NAME" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "Error getting bucket tags"
  tag_set=$(echo "$tags" | jq '.TagSet')
  [[ $tag_set == "[]" ]] || fail "Error:  tags not empty"
  put_bucket_tag "$BUCKET_ONE_NAME" $key $value
  get_bucket_tags "$BUCKET_ONE_NAME" || local get_result_two=$?
  [[ $get_result_two -eq 0 ]] || fail "Error getting bucket tags"
  tag_set_key=$(echo "$tags" | jq '.TagSet[0].Key')
  tag_set_value=$(echo "$tags" | jq '.TagSet[0].Value')
  [[ $tag_set_key == '"'$key'"' ]] || fail "Key mismatch"
  [[ $tag_set_value == '"'$value'"' ]] || fail "Value mismatch"
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
}

# test v1 s3api list objects command
@test "test-s3api-list-objects-v1" {

  local object_one="test-file-one"
  local object_two="test-file-two"
  local object_two_data="test data\n"

  create_test_files "$object_one" "$object_two" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  printf "%s" "$object_two_data" > "$test_file_folder"/"$object_two"
  setup_bucket "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  put_object "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME"/"$object_one" || local put_object_one=$?
  [[ $put_object_one -eq 0 ]] || fail "Failed to add object $object_one"
  put_object "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME"/"$object_two" || local put_object_two=$?
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

  delete_bucket_or_contents "$BUCKET_ONE_NAME"
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
  setup_bucket "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  put_object "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME"/"$object_one" || local put_object_one=$?
  [[ $put_object_one -eq 0 ]] || fail "Failed to add object $object_one"
  put_object "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME"/"$object_two" || local put_object_two=$?
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

  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

# test abilty to set and retrieve object tags
@test "test-set-get-object-tags" {

  local bucket_file="bucket-file"
  local key="test_key"
  local value="test_value"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  local object_path="$BUCKET_ONE_NAME"/"$bucket_file"
  put_object "$test_file_folder"/"$bucket_file" "$object_path" || local put_object=$?
  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket '$BUCKET_ONE_NAME'"
  get_object_tags "$BUCKET_ONE_NAME" $bucket_file || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "Error getting object tags"
  tag_set=$(echo "$tags" | jq '.TagSet')
  [[ $tag_set == "[]" ]] || fail "Error:  tags not empty"
  put_object_tag "$BUCKET_ONE_NAME" $bucket_file $key $value
  get_object_tags "$BUCKET_ONE_NAME" $bucket_file || local get_result_two=$?
  [[ $get_result_two -eq 0 ]] || fail "Error getting object tags"
  tag_set_key=$(echo "$tags" | jq '.TagSet[0].Key')
  tag_set_value=$(echo "$tags" | jq '.TagSet[0].Value')
  [[ $tag_set_key == '"'$key'"' ]] || fail "Key mismatch"
  [[ $tag_set_value == '"'$value'"' ]] || fail "Value mismatch"
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

# test multi-part upload
@test "test-multi-part-upload" {

  local bucket_file="bucket-file"
  bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4
  copy_file "s3://$BUCKET_ONE_NAME/$bucket_file" "$test_file_folder/$bucket_file-copy"
  copy_data=$(<"$test_file_folder"/$bucket_file-copy)
  [[ $bucket_file_data == "$copy_data" ]] || fail "Data doesn't match"
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

# test multi-part upload abort
@test "test-multi-part-upload-abort" {

  local bucket_file="bucket-file"
  bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  printf "%s" "$bucket_file_data" > "$test_file_folder"/$bucket_file
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  abort_multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4
  object_exists "$BUCKET_ONE_NAME/$bucket_file" || exists=$?
  [[ $exists -eq 1 ]] || fail "Upload file exists after abort"
  delete_bucket_or_contents "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}
