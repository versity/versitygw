#!/usr/bin/env bats

source ./tests/util.sh
source ./tests/util_file.sh

# common test for creating, deleting buckets
# param:  "aws" or "s3cmd"
# pass if buckets are properly listed, fail if not
test_common_create_delete_bucket() {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  if [[ $# -ne 1 ]]; then
    fail "create/delete bucket test requires command type"
  fi

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Failed to create bucket"

  bucket_exists "$1" "$BUCKET_ONE_NAME" || local exists_three=$?
  [[ $exists_three -eq 0 ]] || fail "Failed bucket existence check"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME" || local delete_result_two=$?
  [[ $delete_result_two -eq 0 ]] || fail "Failed to delete bucket"
}

test_common_put_object_with_data() {
  if [[ $# -ne 1 ]]; then
    fail "put object test requires command type"
  fi

  local object_name="test-object"
  create_test_files "$object_name" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Error creating test file"
  echo "test data" > "$test_file_folder"/"$object_name"
}

test_common_put_object_no_data() {
  if [[ $# -ne 1 ]]; then
    fail "put object test requires command type"
  fi

  local object_name="test-object"
  create_test_files "$object_name" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Error creating test file"
  test_common_put_object "$1" "$object_name"
}

test_common_put_object() {
  if [[ $# -ne 2 ]]; then
    fail "put object test requires command type, file"
  fi

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  object="$BUCKET_ONE_NAME"/"$2"
  put_object "$1" "$test_file_folder"/"$2" "$object" || local put_object=$?
  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket"
  object_exists "$1" "$object" || local exists_result_one=$?
  [[ $exists_result_one -eq 0 ]] || fail "Object not added to bucket"

  delete_object "$1" "$object" || local delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "Failed to delete object"
  object_exists "$1" "$object" || local exists_result_two=$?
  [[ $exists_result_two -eq 1 ]] || fail "Object not removed from bucket"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files "$2"
}

# common test for listing buckets
# param:  "aws" or "s3cmd"
# pass if buckets are properly listed, fail if not
test_common_list_buckets() {
  if [[ $# -ne 1 ]]; then
    fail "List buckets test requires one argument"
  fi

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local setup_result_one=$?
  [[ $setup_result_one -eq 0 ]] || fail "Bucket one setup error"
  setup_bucket "$1" "$BUCKET_TWO_NAME" || local setup_result_two=$?
  [[ $setup_result_two -eq 0 ]] || fail "Bucket two setup error"

  list_buckets "$1"
  local bucket_one_found=false
  local bucket_two_found=false
  if [ -z "$bucket_array" ]; then
    fail "bucket_array parameter not exported"
  fi
  for bucket in "${bucket_array[@]}"; do
    if [ "$bucket" == "$BUCKET_ONE_NAME" ] || [ "$bucket" == "s3://$BUCKET_ONE_NAME" ]; then
      bucket_one_found=true
    elif [ "$bucket" == "$BUCKET_TWO_NAME" ] || [ "$bucket" == "s3://$BUCKET_TWO_NAME" ]; then
      bucket_two_found=true
    fi
    if [ $bucket_one_found == true ] && [ $bucket_two_found == true ]; then
      break
    fi
  done
  echo $bucket_one_found $bucket_two_found
  if [ $bucket_one_found == false ] || [ $bucket_two_found == false ]; then
    fail "Not all buckets found"
  fi

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_bucket_or_contents "$1" "$BUCKET_TWO_NAME"
}

test_common_list_objects() {
  if [[ $# -ne 1 ]]; then
    echo "common test function for listing objects requires command type"
    return 1
  fi

  object_one="test-file-one"
  object_two="test-file-two"

  create_test_files $object_one $object_two
  echo "test data" > "$test_file_folder"/"$object_one"
  echo "test data 2" > "$test_file_folder"/"$object_two"
  setup_bucket "$1" "$BUCKET_ONE_NAME" || local result_one=$?
  [[ result_one -eq 0 ]] || fail "Error creating bucket"
  put_object "$1" "$test_file_folder"/$object_one "$BUCKET_ONE_NAME"/"$object_one"  || local result_two=$?
  [[ result_two -eq 0 ]] || fail "Error adding object one"
  put_object "$1" "$test_file_folder"/$object_two "$BUCKET_ONE_NAME"/"$object_two" || local result_three=$?
  [[ result_three -eq 0 ]] || fail "Error adding object two"

  list_objects "$1" "$BUCKET_ONE_NAME"
  local object_one_found=false
  local object_two_found=false
  # shellcheck disable=SC2154
  for object in "${object_array[@]}"; do
    if [ "$object" == $object_one ] || [ "$object" == "s3://$BUCKET_ONE_NAME/$object_one" ]; then
      object_one_found=true
    elif [ "$object" == $object_two ] || [ "$object" == "s3://$BUCKET_ONE_NAME/$object_two" ]; then
      object_two_found=true
    fi
  done

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files $object_one $object_two

  if [ $object_one_found != true ] || [ $object_two_found != true ]; then
    fail "$object_one and/or $object_two not listed (all objects: ${object_array[*]})"
  fi
}

test_common_set_get_bucket_tags() {

  if [[ $# -ne 1 ]]; then
    fail "set/get bucket tags test requires command type"
  fi

  local key="test_key"
  local value="test_value"

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  get_bucket_tags "$1" "$BUCKET_ONE_NAME" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "Error getting bucket tags"

  if [[ $1 == 'aws' ]]; then
    if [[ $tags != "" ]]; then
      tag_set=$(echo "$tags" | sed '1d' | jq '.TagSet')
      [[ $tag_set == "[]" ]] || fail "Error:  tags not empty: $tags"
    fi
  else
    [[ $tags == "" ]] || [[ $tags =~ "No tags found" ]] || fail "Error:  tags not empty: $tags"
  fi

  put_bucket_tag "$1" "$BUCKET_ONE_NAME" $key $value
  get_bucket_tags "$1" "$BUCKET_ONE_NAME" || local get_result_two=$?
  [[ $get_result_two -eq 0 ]] || fail "Error getting bucket tags"

  local tag_set_key
  local tag_set_value
  if [[ $1 == 'aws' ]]; then
    tag_set_key=$(echo "$tags" | sed '1d' | jq '.TagSet[0].Key')
    tag_set_value=$(echo "$tags" | sed '1d' | jq '.TagSet[0].Value')
    [[ $tag_set_key == '"'$key'"' ]] || fail "Key mismatch"
    [[ $tag_set_value == '"'$value'"' ]] || fail "Value mismatch"
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    [[ $tag_set_key == "$key" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$value" ]] || fail "Value mismatch"
  fi
  delete_bucket_tags "$1" "$BUCKET_ONE_NAME"
  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
}

test_common_set_get_object_tags() {

  if [[ $# -ne 1 ]]; then
    echo "get/set object tags missing command type"
    return 1
  fi

  local bucket_file="bucket-file"
  local key="test_key"
  local value="test_value"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  local object_path="$BUCKET_ONE_NAME"/"$bucket_file"
  put_object "$1" "$test_file_folder"/"$bucket_file" "$object_path" || local put_object=$?
  [[ $put_object -eq 0 ]] || fail "Failed to add object to bucket '$BUCKET_ONE_NAME'"

  get_object_tags "$1" "$BUCKET_ONE_NAME" $bucket_file || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "Error getting object tags"
  if [[ $1 == 'aws' ]]; then
    tag_set=$(echo "$tags" | sed '1d' | jq '.TagSet')
    [[ $tag_set == "[]" ]] || fail "Error:  tags not empty"
  elif [[ ! $tags == *"No tags found"* ]]; then
    fail "no tags found (tags: $tags)"
  fi

  put_object_tag "$1" "$BUCKET_ONE_NAME" $bucket_file $key $value
  get_object_tags "$1" "$BUCKET_ONE_NAME" $bucket_file || local get_result_two=$?
  [[ $get_result_two -eq 0 ]] || fail "Error getting object tags"
  if [[ $1 == 'aws' ]]; then
    tag_set_key=$(echo "$tags" | sed '1d' | jq '.TagSet[0].Key')
    tag_set_value=$(echo "$tags" | sed '1d' | jq '.TagSet[0].Value')
    [[ $tag_set_key == '"'$key'"' ]] || fail "Key mismatch"
    [[ $tag_set_value == '"'$value'"' ]] || fail "Value mismatch"
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    [[ $tag_set_key == "$key" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$value" ]] || fail "Value mismatch"
  fi

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

test_common_multipart_upload() {
  if [[ $# -ne 1 ]]; then
    echo "multipart upload command missing command type"
    return 1
  fi
  bucket_file="largefile"

  create_large_file "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test file for multipart upload"

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  put_object "$1" "$test_file_folder"/$bucket_file "$BUCKET_ONE_NAME/$bucket_file" || local put_result=$?
  [[ $put_result -eq 0 ]] || fail "failed to copy file"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

test_common_presigned_url_utf8_chars() {

  if [[ $# -ne 1 ]]; then
    echo "presigned url command missing command type"
    return 1
  fi

  local bucket_file="my-$%^&*;"
  local bucket_file_copy="bucket-file-copy"
  bucket_file_data="test file\n"

  create_test_files "$bucket_file" || local created=$?
  printf "%s" "$bucket_file_data" > "$test_file_folder"/"$bucket_file"
  setup_bucket "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  put_object "$1" "$test_file_folder"/"$bucket_file" "$BUCKET_ONE_NAME"/"$bucket_file" || put_result=$?
  [[ $put_result -eq 0 ]] || fail "Failed to add object $bucket_file"

  create_presigned_url "$1" "$BUCKET_ONE_NAME" "$bucket_file" || presigned_result=$?
  [[ $presigned_result -eq 0 ]] || fail "presigned url creation failure"

  error=$(curl -k -v "$presigned_url" -o "$test_file_folder"/"$bucket_file_copy") || curl_result=$?
  if [[ $curl_result -ne 0 ]]; then
    fail "error downloading file with curl: $error"
  fi
  compare_files "$test_file_folder"/"$bucket_file" "$test_file_folder"/"$bucket_file_copy" || compare_result=$?
  if [[ $compare_result -ne 0 ]]; then
    echo "file one: $(cat "$test_file_folder"/"$bucket_file")"
    echo "file two: $(cat "$test_file_folder"/"$bucket_file_copy")"
    fail "files don't match"
  fi

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files "$bucket_file" "$bucket_file_copy"
}
