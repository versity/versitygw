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
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_policy.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object.sh

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

@test "test_copy_object" {
  test_common_copy_object "s3api"
}

# test creation and deletion of bucket on versitygw
@test "test_create_delete_bucket_aws" {
  test_common_create_delete_bucket "aws"
}

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
  error=$(aws --no-verify-ssl s3api copy-object --copy-source "$BUCKET_ONE_NAME/$bucket_file" --key "$bucket_file" --bucket "$BUCKET_TWO_NAME" 2>&1) || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Error copying file: $error"
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

# test ability to retrieve bucket ACLs
@test "test_get_bucket_acl" {

  setup_bucket "aws" "$BUCKET_ONE_NAME" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"

  get_bucket_acl "s3api" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"

  id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq '.Owner.ID')
  [[ $id == '"'"$AWS_ACCESS_KEY_ID"'"' ]] || fail "Acl mismatch"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
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

# test ability to delete multiple objects from bucket
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

# test abilty to set and retrieve bucket tags
@test "test-set-get-delete-bucket-tags" {
  test_common_set_get_delete_bucket_tags "aws"
}

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

  list_multipart_uploads "$BUCKET_ONE_NAME" "$test_file_folder"/"$bucket_file_one" "$test_file_folder"/"$bucket_file_two"
  [[ $? -eq 0 ]] || fail "failed to list multipart uploads"

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

@test "test_delete_object_tagging" {
  test_common_delete_object_tagging "aws"
}

@test "test_get_bucket_location" {
  test_common_get_bucket_location "aws"
}

@test "test_get_put_delete_bucket_policy" {
  test_common_get_put_delete_bucket_policy "aws"
}