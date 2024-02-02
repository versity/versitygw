#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_posix.sh

# test that changes to local folders and files are reflected on S3
@test "test_local_creation_deletion" {

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

# test head-object command
@test "test_head_object" {

  local bucket_name="versity-gwtest-head-object"
  local object_name="object-one"

  touch "$object_name"

  if [ -e "$LOCAL_FOLDER"/$bucket_name/$object_name ]; then
    chmod 755 "$LOCAL_FOLDER"/$bucket_name/$object_name
  fi
  check_and_create_bucket $bucket_name || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"
  put_object "$object_name" "$bucket_name"/"$object_name"  || local result="$?"
  [[ result -eq 0 ]] || fail "Error adding object one"
  chmod 000 "$LOCAL_FOLDER"/$bucket_name/$object_name
  sleep 1
  object_is_accessible $bucket_name $object_name || local accessible=$?
  [[ $accessible -eq 1 ]] || fail "Object should be inaccessible"
  chmod 755 "$LOCAL_FOLDER"/$bucket_name/$object_name
  sleep 1
  object_is_accessible $bucket_name $object_name || local accessible_two=$?
  [[ $accessible_two -eq 0 ]] || fail "Object should be accessible"
  delete_object $bucket_name/$object_name
  delete_bucket $bucket_name
}

# check info, accessiblity of bucket
@test "test_get_bucket_info" {

  local bucket_name="versity-gwtest-get-bucket-info"

  if [ -e "$LOCAL_FOLDER"/$bucket_name ]; then
    chmod 755 "$LOCAL_FOLDER"/$bucket_name
    sleep 1
  else
    create_bucket $bucket_name || local created=$?
    [[ $created -eq 0 ]] || fail "Error creating bucket"
  fi
  chmod 000 "$LOCAL_FOLDER"/$bucket_name
  sleep 1
  bucket_is_accessible $bucket_name || local accessible=$?
  [[ $accessible -eq 1 ]] || fail "Bucket should be inaccessible"
  chmod 755 "$LOCAL_FOLDER"/$bucket_name
  sleep 1
  bucket_is_accessible $bucket_name || local accessible_two=$?
  [[ $accessible_two -eq 0 ]] || fail "Bucket should be accessible"
  delete_bucket $bucket_name
}
