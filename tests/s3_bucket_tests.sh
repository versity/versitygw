#!/usr/bin/env bats

source ./tests/tests.sh

# create an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
create_bucket() {
  if [ $# -ne 1 ]; then
    echo "create bucket missing bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 mb s3://"$1" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error creating bucket: $error"
    return 1
  fi
  return 0
}

# delete an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket() {
  if [ $# -ne 1 ]; then
    echo "delete bucket missing bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 rb s3://"$1" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    else
      echo "error deleting bucket: $error"
      return 1
    fi
  fi
  return 0
}

# check if bucket exists
# param:  bucket name
# return 0 for true, 1 for false, 2 for error
bucket_exists() {
  if [ $# -ne 1 ]; then
    echo "bucket exists check missing bucket name"
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws s3 ls s3://"$1" 2>&1) || exit_code="$?"
  echo "Exit code: $exit_code, error: $error"
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]] || [[ "$error" == *"Access Denied"* ]]; then
      return 1
    else
      echo "error checking if bucket exists: $error"
      return 2
    fi
  fi
  return 0
}

# create bucket if it doesn't exist
# param:  bucket name
# return 0 for success, 1 for failure
check_and_create_bucket() {
  if [ $# -ne 1 ]; then
    echo "bucket creation function requires bucket name"
    return 1
  fi
  local exists_result
  bucket_exists "$1" || exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    echo "Bucket existence check error"
    return 1
  fi
  local create_result
  if [[ $exists_result -eq 1 ]]; then
    create_bucket "$1" || create_result=$?
    if [[ $create_result -ne 0 ]]; then
      echo "Error creating bucket"
      return 1
    fi
  fi
  return 0
}

# check if object exists on S3 via gateway
# param:  object path
# return 0 for true, 1 for false, 2 for error
object_exists() {
  if [ $# -ne 1 ]; then
    echo "object exists check missing object name"
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws s3 ls s3://"$1" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == "" ]]; then
      return 1
    else
      echo "error checking if object exists: $error"
      return 2
    fi
  fi
  return 0
}

# add object to versitygw
# params:  source file, destination copy location
# return 0 for success, 1 for failure
put_object() {
  if [ $# -ne 2 ]; then
    echo "put object command requires source, destination"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 cp "$1" s3://"$2" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  return 0
}

# add object to versitygw if it doesn't exist
# params:  source file, destination copy location
# return 0 for success or already exists, 1 for failure
check_and_put_object() {
  if [ $# -ne 2 ]; then
    echo "check and put object function requires source, destination"
    return 1
  fi
  object_exists "$2" || local exists_result=$?
  if [ $exists_result -eq 2 ]; then
    echo "error checking if object exists"
    return 1
  fi
  if [ $exists_result -eq 1 ]; then
    put_object "$1" "$2" || local put_result=$?
    if [ $put_result -ne 0 ]; then
      echo "error adding object"
      return 1
    fi
  fi
  return 0
}

# delete object from versitygw
# param:  object location
# return 0 for success, 1 for failure
delete_object() {
  if [ $# -ne 1 ]; then
    echo "delete object command requires object parameter"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 rm s3://"$1" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error deleting object: $error"
    return 1
  fi
  return 0
}

# list buckets on versitygw
# no params
# export bucket_array (bucket names) on success, return 1 for failure
list_buckets() {
  local exit_code=0
  local output
  output=$(aws s3 ls 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error listing buckets: $output"
    return 1
  fi

  bucket_array=()
  while IFS= read -r line; do
    bucket_name=$(echo "$line" | awk '{print $NF}')
    bucket_array+=("$bucket_name")
  done <<< "$output"

  export bucket_array
}

# list objects on versitygw, in bucket or folder
# param:  path of bucket or folder
# export object_array (object names) on success, return 1 for failure
list_objects() {
  if [ $# -ne 1 ]; then
    echo "list objects command requires bucket or folder"
    return 1
  fi
  local exit_code=0
  local output
  output=$(aws s3 ls s3://"$1" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error listing objects: $output"
    return 1
  fi

  object_array=()
  while IFS= read -r line; do
    object_name=$(echo "$line" | awk '{print $NF}')
    object_array+=("$object_name")
  done <<< "$output"

  export object_array
}

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
@test test_list_objects {

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
