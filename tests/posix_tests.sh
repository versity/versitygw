#!/usr/bin/env bats

source ./tests/tests.sh

# check if object exists both on S3 and locally
# param:  object path
# 0 for yes, 1 for no, 2 for error
object_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "object existence check requires single name parameter"
    return 2
  fi
  object_exists "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if object exists"
    return 2
  fi
  if [[ $exist_result -eq 1 ]]; then
    echo "Error:  object doesn't exist remotely"
    return 1
  fi
  if [[ ! -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  object doesn't exist locally"
    return 1
  fi
  return 0
}

# check if object doesn't exist both on S3 and locally
# param:  object path
# return 0 for doesn't exist, 1 for still exists, 2 for error
object_not_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "object non-existence check requires single name parameter"
    return 2
  fi
  object_exists "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if object doesn't exist"
    return 2
  fi
  if [[ $exist_result -eq 0 ]]; then
    echo "Error:  object exists remotely"
    return 1
  fi
  if [[ -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  object exists locally"
    return 1
  fi
  return 0
}

# check if a bucket doesn't exist both on S3 and on gateway
# param: bucket name
# return:  0 for doesn't exist, 1 for does, 2 for error
bucket_not_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "bucket existence check requires single name parameter"
    return 2
  fi
  bucket_exists "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if bucket exists"
    return 2
  fi
  if [[ $exist_result -eq 0 ]]; then
    echo "Error:  bucket exists remotely"
    return 1
  fi
  if [[ -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  bucket exists locally"
    return 1
  fi
  return 0
}

# check if a bucket exists both on S3 and on gateway
# param: bucket name
# return:  0 for yes, 1 for no, 2 for error
bucket_exists_remote_and_local() {
  if [ $# -ne 1 ]; then
    echo "bucket existence check requires single name parameter"
    return 2
  fi
  bucket_exists "$1" || local exist_result=$?
  if [[ $exist_result -eq 2 ]]; then
    echo "Error checking if bucket exists"
    return 2
  fi
  if [[ $exist_result -eq 1 ]]; then
    echo "Error:  bucket doesn't exist remotely"
    return 1
  fi
  if [[ ! -e "$LOCAL_FOLDER"/"$1" ]]; then
    echo "Error:  bucket doesn't exist locally"
    return 1
  fi
  return 0
}

# test that changes to local folders and files are reflected on S3
@test test_local_creation_deletion {

  local bucket_name="versity-gwtest-put-object-test"
  local object_name="test-object"

  bucket_exists_remote_and_local $bucket_name || local bucket_exists=$?
  if [[ $bucket_exists -eq 2 ]]; then
    fail "Bucket existence check error"
  fi
  local object="$bucket_name"/"$object_name"
  if [[ $bucket_exists -eq 0 ]]; then
    object_exists_remote_and_local "$object" || local object_exists=$?
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
  mkdir "$LOCAL_FOLDER"/$bucket_name
  touch "$LOCAL_FOLDER"/$object
  bucket_exists_remote_and_local $bucket_name || local bucket_exists_two=$?
  [[ $bucket_exists_two -eq 0 ]] || fail "Failed bucket existence check"
  object_exists_remote_and_local $object || local object_exists_two=$?
  [[ $object_exists_two -eq 0 ]] || fail "Failed object existence check"
  rm "$LOCAL_FOLDER"/$object
  sleep 1
  object_not_exists_remote_and_local $object || local object_deleted=$?
  [[ $object_deleted -eq 0 ]] || fail "Failed object deletion check"
  rmdir "$LOCAL_FOLDER"/$bucket_name
  sleep 1
  bucket_not_exists_remote_and_local $bucket_name || local bucket_deleted=$?
  [[ $bucket_deleted -eq 0 ]] || fail "Failed bucket deletion check"
}

