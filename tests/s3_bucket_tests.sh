#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh

# test creation and deletion of bucket on versitygw
@test "create_delete_bucket_test" {

  local bucket_name="versity-gwtest-create-delete-bucket-test"

  bucket_exists $bucket_name || local exists=$?
  if [[ $exists -eq 2 ]]; then
    fail "Bucket existence check error"
  fi
  if [[ $exists -eq 0 ]]; then
    delete_bucket $bucket_name || local delete_result=$?
    [[ $delete_result -eq 0 ]] || fail "Failed to delete bucket"
    bucket_exists $bucket_name || local exists_two=$?
    [[ $exists_two -eq 1 ]] || fail "Failed bucket deletion"
  fi
  create_bucket $bucket_name || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Failed to create bucket"
  bucket_exists $bucket_name || local exists_three=$?
  [[ $exists_three -eq 0 ]] || fail "Failed bucket existence check"
  delete_bucket $bucket_name || local delete_result_two=$?
  [[ $delete_result_two -eq 0 ]] || fail "Failed to delete bucket"
}

# test adding and removing an object on versitygw
@test "put_object_test" {

  local bucket_name="versity-gwtest-put-object-test"
  local object_name="test-object"

  bucket_exists $bucket_name || local bucket_exists=$?
  if [[ $bucket_exists -eq 2 ]]; then
    fail "Bucket existence check error"
  fi
  local object="$bucket_name"/"$object_name"
  if [[ $bucket_exists -eq 0 ]]; then
    object_exists "$object" || local object_exists=$?
    if [[ $object_exists -eq 2 ]]; then
      fail "Object existence check error"
    fi
    if [[ $object_exists -eq 0 ]]; then
      delete_object "$object" || local delete_object=$?
      [[ $delete_object -eq 0 ]] || fail "Failed to delete object"
    fi
    delete_bucket $bucket_name || local delete_bucket=$?
    [[ $delete_bucket -eq 0 ]] || fail "Failed to delete bucket"
  fi
  touch "$object_name"
  create_bucket $bucket_name || local create_bucket=$?
  [[ $create_bucket -eq 0 ]] || fail "Failed to create bucket"
  put_object "$object_name" "$object" || local put_object=$?
  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket"
  object_exists "$object" || local object_exists_two=$?
  [[ $object_exists_two -eq 0 ]] || fail "Object not added to bucket"
  delete_object "$object" || local delete_object_two=$?
  [[ $delete_object_two -eq 0 ]] || fail "Failed to delete object"
  delete_bucket $bucket_name || local delete_bucket=$?
  [[ $delete_bucket -eq 0 ]] || fail "Failed to delete bucket"
  rm "$object_name"
}

# test listing buckets on versitygw
@test "test_list_buckets" {

  bucket_name_one="versity-gwtest-list-one"
  bucket_name_two="versity-gwtest-list-two"

  bucket_exists $bucket_name_one || local exists=$?
  if [[ $exists -eq 2 ]]; then
    fail "Bucket existence check error"
  fi
  if [[ $exists -eq 1 ]]; then
    create_bucket $bucket_name_one || local bucket_create_one=$?
    [[ $bucket_create_one -eq 0 ]] || fail "Failed to create bucket"
  fi
  bucket_exists $bucket_name_two || local exists_two=$?
  if [[ $exists_two -eq 2 ]]; then
    fail "Bucket existence check error"
  fi
  if [[ $exists_two -eq 1 ]]; then
    create_bucket $bucket_name_two || local bucket_create_two=$?
    [[ $bucket_create_two -eq 0 ]] || fail "Failed to create bucket"
  fi
  list_buckets
  local bucket_one_found=false
  local bucket_two_found=false
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == $bucket_name_one ]; then
      bucket_one_found=true
    elif [ "$bucket" == $bucket_name_two ]; then
      bucket_two_found=true
    fi
    if [ $bucket_one_found == true ] && [ $bucket_two_found == true ]; then
      return
    fi
  done
  fail "$bucket_name_one and/or $bucket_name_two not listed (all buckets: ${bucket_array[*]})"
  delete_bucket $bucket_name_one || local deleted_one=$?
  [[ $deleted_one -eq 0 ]] || fail "Failed to delete bucket one"
  delete_bucket $bucket_name_two || local deleted_two=$?
  [[ $deleted_two -eq 0 ]] || fail "Failed to delete bucket one"
}

# test listing a bucket's objects on versitygw
@test "test_list_objects" {

  bucket_name="versity-gwtest-list-object"
  object_one="test-file-one"
  object_two="test-file-two"

  touch $object_one $object_two
  check_and_create_bucket $bucket_name || local result_one=$?
  [[ result_one -eq 0 ]] || fail "Error creating bucket"
  put_object $object_one "$bucket_name"/"$object_one"  || local result_two=$?
  [[ result_two -eq 0 ]] || fail "Error adding object one"
  put_object $object_two "$bucket_name"/"$object_two" || local result_three=$?
  [[ result_three -eq 0 ]] || fail "Error adding object two"
  list_objects $bucket_name
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
  delete_object "$bucket_name"/"$object_one"
  delete_object "$bucket_name"/"$object_two"
  delete_bucket $bucket_name
  rm $object_one $object_two
}

# test ability to retrieve bucket ACLs
@test "test_get_bucket_acl" {

  local bucket_name="versity-gwtest-get-bucket-acl"
  check_and_create_bucket $bucket_name || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"
  get_bucket_acl $bucket_name || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"
  id=$(echo "$acl" | jq '.Owner.ID')
  [[ $id == '"'"$AWS_ACCESS_KEY_ID"'"' ]] || fail "Acl mismatch"
  delete_bucket $bucket_name
}

# test ability to delete multiple objects from bucket
@test "test_delete_objects" {

  local bucket_name="versity-gwtest-delete-objects"
  local object_one="test-file-one"
  local object_two="test-file-two"

  touch "$object_one" "$object_two"
  check_and_create_bucket $bucket_name || local result_one=$?
  [[ $result_one -eq 0 ]] || fail "Error creating bucket"
  put_object "$object_one" "$bucket_name"/"$object_one"  || local result_two=$?
  [[ $result_two -eq 0 ]] || fail "Error adding object one"
  put_object "$object_two" "$bucket_name"/"$object_two" || local result_three=$?
  [[ $result_three -eq 0 ]] || fail "Error adding object two"

  error=$(aws s3api delete-objects --bucket $bucket_name --delete '{
    "Objects": [
      {"Key": "test-file-one"},
      {"Key": "test-file-two"}
    ]
  }') || local result=$?
  [[ $result -eq 0 ]] || fail "Error deleting objects: $error"

  object_exists "$bucket_name"/"$object_one" || local exists_one=$?
  [[ $exists_one -eq 1 ]] || fail "Object one not deleted"
  object_exists "$bucket_name"/"$object_two" || local exists_two=$?
  [[ $exists_two -eq 1 ]] || fail "Object two not deleted"

  delete_bucket $bucket_name
  rm "$object_one" "$object_two"
}
