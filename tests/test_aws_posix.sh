#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_bucket_create.sh
source ./tests/util_file.sh
source ./tests/util_posix.sh
source ./tests/commands/copy_object.sh

# test that changes to local folders and files are reflected on S3
@test "test_local_creation_deletion" {

  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  local object_name="test-object"

  if [[ -e "$LOCAL_FOLDER"/"$BUCKET_ONE_NAME" ]]; then
    rm -rf "${LOCAL_FOLDER:?}"/"${BUCKET_ONE_NAME:?}"
  fi

  mkdir "$LOCAL_FOLDER"/"$BUCKET_ONE_NAME"
  local object="$BUCKET_ONE_NAME"/"$object_name"
  touch "$LOCAL_FOLDER"/"$object"

  bucket_exists_remote_and_local "$BUCKET_ONE_NAME" || local bucket_exists_two=$?
  [[ $bucket_exists_two -eq 0 ]] || fail "Failed bucket existence check"
  object_exists_remote_and_local "$object" || local object_exists_two=$?
  [[ $object_exists_two -eq 0 ]] || fail "Failed object existence check"

  rm "$LOCAL_FOLDER"/"$object"
  sleep 1
  object_not_exists_remote_and_local "$object" || local object_deleted=$?
  [[ $object_deleted -eq 0 ]] || fail "Failed object deletion check"

  rmdir "$LOCAL_FOLDER"/"$BUCKET_ONE_NAME"
  sleep 1
  bucket_not_exists_remote_and_local "$BUCKET_ONE_NAME" || local bucket_deleted=$?
  [[ $bucket_deleted -eq 0 ]] || fail "Failed bucket deletion check"
}

# test head-object command
@test "test_head_object" {

  local bucket_name=$BUCKET_ONE_NAME
  local object_name="object-one"

  create_test_files $object_name
  if [ -e "$LOCAL_FOLDER"/"$bucket_name"/$object_name ]; then
    chmod 755 "$LOCAL_FOLDER"/"$bucket_name"/$object_name
  fi
  setup_bucket "aws" "$bucket_name" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"
  copy_object "aws" "$test_file_folder"/"$object_name" "$bucket_name"/"$object_name"  || local result="$?"
  [[ result -eq 0 ]] || fail "Error adding object one"

  chmod 000 "$LOCAL_FOLDER"/"$bucket_name"/$object_name
  sleep 1
  object_is_accessible "$bucket_name" $object_name || local accessible=$?
  [[ $accessible -eq 1 ]] || fail "Object should be inaccessible"

  chmod 755 "$LOCAL_FOLDER"/"$bucket_name"/$object_name
  sleep 1
  object_is_accessible "$bucket_name" $object_name || local accessible_two=$?
  [[ $accessible_two -eq 0 ]] || fail "Object should be accessible"

  delete_object "aws" "$bucket_name"/$object_name
  delete_bucket_or_contents "aws" "$bucket_name"
  delete_test_files $object_name
}

# check info, accessiblity of bucket
@test "test_get_bucket_info" {

  if [ -e "$LOCAL_FOLDER"/"$BUCKET_ONE_NAME" ]; then
    chmod 755 "$LOCAL_FOLDER"/"$BUCKET_ONE_NAME"
    sleep 1
  else
    setup_bucket "aws" "$BUCKET_ONE_NAME" || local created=$?
    [[ $created -eq 0 ]] || fail "Error creating bucket"
  fi

  chmod 000 "$LOCAL_FOLDER"/"$BUCKET_ONE_NAME"
  sleep 1
  bucket_is_accessible "$BUCKET_ONE_NAME" || local accessible=$?
  [[ $accessible -eq 1 ]] || fail "Bucket should be inaccessible"

  chmod 755 "$LOCAL_FOLDER"/"$BUCKET_ONE_NAME"
  sleep 1
  bucket_is_accessible "$BUCKET_ONE_NAME" || local accessible_two=$?
  [[ $accessible_two -eq 0 ]] || fail "Bucket should be accessible"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}
