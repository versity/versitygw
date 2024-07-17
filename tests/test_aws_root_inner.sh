#!/usr/bin/env bats

source ./tests/commands/delete_objects.sh

test_abort_multipart_upload_aws_root() {
  local bucket_file="bucket-file"

  create_test_files "$bucket_file" || fail "error creating test files"
  # shellcheck disable=SC2154
  dd if=/dev/urandom of="$test_file_folder/$bucket_file" bs=5M count=1 || fail "error creating test file"

  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  run_then_abort_multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || fail "abort failed"

  if object_exists "aws" "$BUCKET_ONE_NAME" "$bucket_file"; then
    fail "Upload file exists after abort"
  fi

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

test_complete_multipart_upload_aws_root() {
  local bucket_file="bucket-file"

  create_test_files "$bucket_file" || fail "error creating test files"
  dd if=/dev/urandom of="$test_file_folder/$bucket_file" bs=5M count=1 || fail "error creating test file"

  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "failed to create bucket '$BUCKET_ONE_NAME'"

  multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || fail "error performing multipart upload"

  download_and_compare_file "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder/$bucket_file-copy" || fail "error downloading and comparing file"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

test_create_multipart_upload_properties_aws_root() {
  local bucket_file="bucket-file"

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
    later=$(date -j -v +15S -f "%Y-%m-%dT%H:%M:%S" "$now" +"%Y-%m-%dT%H:%M:%S")
  else
    now=$(date +"%Y-%m-%dT%H:%M:%S")
    later=$(date -d "$now 15 seconds" +"%Y-%m-%dT%H:%M:%S")
  fi

  create_test_files "$bucket_file" || fail "error creating test file"
  dd if=/dev/urandom of="$test_file_folder/$bucket_file" bs=5M count=1 || fail "error creating test file"

  delete_bucket_or_contents_if_exists "s3api" "$BUCKET_ONE_NAME" || fail "error deleting bucket, or checking for existence"
  # in static bucket config, bucket will still exist
  bucket_exists "s3api" "$BUCKET_ONE_NAME" || local exists_result=$?
  [[ $exists_result -ne 2 ]] || fail "error checking for bucket existence"
  if [[ $exists_result -eq 1 ]]; then
    create_bucket_object_lock_enabled "$BUCKET_ONE_NAME" || fail "error creating bucket"
  fi
  get_object_lock_configuration "$BUCKET_ONE_NAME" || fail "error getting log config"
  # shellcheck disable=SC2154
  log 5 "LOG CONFIG:  $log_config"

  log 5 "LATER: $later"
  multipart_upload_with_params "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 \
    "$expected_content_type" \
    "{\"$expected_meta_key\": \"$expected_meta_val\"}" \
    "$expected_hold_status" \
    "$expected_retention_mode" \
    "$later" \
    "$expected_tag_key=$expected_tag_val" || fail "error performing multipart upload"

  head_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting metadata"
  # shellcheck disable=SC2154
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
  [[ $retain_until_date == "$later"* ]] || fail "retention date mismatch ($retain_until_date, $five_seconds_later)"

  get_object_tagging "aws" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting tagging"
  # shellcheck disable=SC2154
  log 5 "tags: $tags"
  tag_key=$(echo "$tags" | jq -r ".TagSet[0].Key")
  [[ $tag_key == "$expected_tag_key" ]] || fail "tag mismatch ($tag_key, $expected_tag_key)"
  tag_val=$(echo "$tags" | jq -r ".TagSet[0].Value")
  [[ $tag_val == "$expected_tag_val" ]] || fail "tag mismatch ($tag_val, $expected_tag_val)"

  put_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" "OFF" || fail "error disabling legal hold"
  head_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting metadata"

  get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder/$bucket_file-copy" || fail "error getting object"
  compare_files "$test_file_folder/$bucket_file" "$test_file_folder/$bucket_file-copy" || fail "files not equal"

  sleep 15

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

test_delete_objects_aws_root() {
  local object_one="test-file-one"
  local object_two="test-file-two"

  create_test_files "$object_one" "$object_two" || fail "error creating test files"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error creating bucket"

  put_object "s3api" "$test_file_folder"/"$object_one" "$BUCKET_ONE_NAME" "$object_one" || fail "error adding object one"
  put_object "s3api" "$test_file_folder"/"$object_two" "$BUCKET_ONE_NAME" "$object_two" || fail "error adding object two"

  delete_objects "$BUCKET_ONE_NAME" "$object_one" "$object_two" || fail "error deleting objects"

  object_exists "s3api" "$BUCKET_ONE_NAME" "$object_one" || local object_one_exists_result=$?
  [[ $object_one_exists_result -eq 1 ]] || fail "object $object_one not deleted"
  object_exists "s3api" "$BUCKET_ONE_NAME" "$object_two" || local object_two_exists_result=$?
  [[ $object_two_exists_result -eq 1 ]] || fail "object $object_two not deleted"

  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one" "$object_two"
}

test_get_bucket_acl_aws_root() {
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"

  get_bucket_acl "s3api" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"

  # shellcheck disable=SC2154
  id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq '.Owner.ID')
  [[ $id == '"'"$AWS_ACCESS_KEY_ID"'"' ]] || fail "Acl mismatch"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

test_get_object_full_range_aws_root() {
  bucket_file="bucket_file"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  echo -n "0123456789" > "$test_file_folder/$bucket_file"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error putting object"
  get_object_with_range "$BUCKET_ONE_NAME" "$bucket_file" "bytes=9-15" "$test_file_folder/$bucket_file-range" || fail "error getting range"
  [[ "$(cat "$test_file_folder/$bucket_file-range")" == "9" ]] || fail "byte range not copied properly"
}

test_get_object_invalid_range_aws_root() {
  bucket_file="bucket_file"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error putting object"
  get_object_with_range "$BUCKET_ONE_NAME" "$bucket_file" "bytes=0-0" "$test_file_folder/$bucket_file-range" || local get_result=$?
  [[ $get_result -ne 0 ]] || fail "Get object with zero range returned no error"
}

test_put_object_aws_root() {
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

test_create_bucket_invalid_name_aws_root() {
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    return
  fi

  create_bucket_invalid_name "aws" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Invalid name test failed"

  # shellcheck disable=SC2154
  [[ "$bucket_create_error" == *"Invalid bucket name "* ]] || fail "unexpected error:  $bucket_create_error"
}

test_get_object_attributes_aws_root() {
  bucket_file="bucket_file"

  create_test_files "$bucket_file" || fail "error creating test files"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  put_object "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || fail "failed to add object to bucket"
  get_object_attributes "$BUCKET_ONE_NAME" "$bucket_file" || failed "failed to get object attributes"
  # shellcheck disable=SC2154
  has_object_size=$(echo "$attributes" | jq -e '.ObjectSize' 2>&1) || fail "error checking for ObjectSize parameters: $has_object_size"
  if [[ $has_object_size -eq 0 ]]; then
    object_size=$(echo "$attributes" | jq -r ".ObjectSize")
    [[ $object_size == 0 ]] || fail "Incorrect object size: $object_size"
  else
    fail "ObjectSize parameter missing: $attributes"
  fi
  delete_bucket_or_contents "s3api" "$BUCKET_ONE_NAME"
}

test_get_put_object_legal_hold_aws_root() {
  # bucket must be created with lock for legal hold
  if [[ $RECREATE_BUCKETS == false ]]; then
    return
  fi

  bucket_file="bucket_file"
  username="ABCDEFG"
  password="HIJKLMN"

  legal_hold_retention_setup "$username" "$password" "$bucket_file"

  get_object_lock_configuration "$BUCKET_ONE_NAME" || fail "error getting lock configuration"
  # shellcheck disable=SC2154
  log 5 "$lock_config"
  enabled=$(echo "$lock_config" | jq -r ".ObjectLockConfiguration.ObjectLockEnabled")
  [[ $enabled == "Enabled" ]] || fail "ObjectLockEnabled should be 'Enabled', is '$enabled'"

  put_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" "ON" || fail "error putting legal hold on object"
  get_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting object legal hold status"
  # shellcheck disable=SC2154
  log 5 "$legal_hold"
  hold_status=$(echo "$legal_hold" | grep -v "InsecureRequestWarning" | jq -r ".LegalHold.Status" 2>&1) || fail "error obtaining hold status: $hold_status"
  [[ $hold_status == "ON" ]] || fail "Status should be 'ON', is '$hold_status'"

  echo "fdkljafajkfs" > "$test_file_folder/$bucket_file"
  if put_object_with_user "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$password"; then
    fail "able to overwrite object with hold"
  fi
  # shellcheck disable=SC2154
  #[[ $put_object_error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $put_object_error"

  if delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$password"; then
    fail "able to delete object with hold"
  fi
  # shellcheck disable=SC2154
  [[ $delete_object_error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $delete_object_error"
  put_object_legal_hold "$BUCKET_ONE_NAME" "$bucket_file" "OFF" || fail "error removing legal hold on object"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$password" || fail "error deleting object after removing legal hold"

  delete_bucket_recursive "s3api" "$BUCKET_ONE_NAME"
}

test_get_put_object_retention_aws_root() {
  # bucket must be created with lock for legal hold
  if [[ $RECREATE_BUCKETS == false ]]; then
    return
  fi

  bucket_file="bucket_file"
  username="ABCDEFG"
  secret_key="HIJKLMN"

  legal_hold_retention_setup "$username" "$secret_key" "$bucket_file"

  get_object_lock_configuration "$BUCKET_ONE_NAME" || fail "error getting lock configuration"
  log 5 "$lock_config"
  enabled=$(echo "$lock_config" | jq -r ".ObjectLockConfiguration.ObjectLockEnabled")
  [[ $enabled == "Enabled" ]] || fail "ObjectLockEnabled should be 'Enabled', is '$enabled'"

  if [[ "$OSTYPE" == "darwin"* ]]; then
    retention_date=$(date -v+2d +"%Y-%m-%dT%H:%M:%S")
  else
    retention_date=$(date -d "+2 days" +"%Y-%m-%dT%H:%M:%S")
  fi
  put_object_retention "$BUCKET_ONE_NAME" "$bucket_file" "GOVERNANCE" "$retention_date" || fail "failed to add object retention"
  get_object_retention "$BUCKET_ONE_NAME" "$bucket_file" || fail "failed to get object retention"
  log 5 "$retention"
  retention=$(echo "$retention" | grep -v "InsecureRequestWarning")
  mode=$(echo "$retention" | jq -r ".Retention.Mode")
  retain_until_date=$(echo "$retention" | jq -r ".Retention.RetainUntilDate")
  [[ $mode == "GOVERNANCE" ]] || fail "retention mode should be governance, is $mode"
  [[ $retain_until_date == "$retention_date"* ]] || fail "retain until date should be $retention_date, is $retain_until_date"

  echo "fdkljafajkfs" > "$test_file_folder/$bucket_file"
  put_object_with_user "s3api" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key" || local put_result=$?
  [[ $put_result -ne 0 ]] || fail "able to overwrite object with hold"
  # shellcheck disable=SC2154
  [[ $error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $error"

  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$bucket_file" "$username" "$secret_key" || local delete_result=$?
  [[ $delete_result -ne 0 ]] || fail "able to delete object with hold"
  [[ $error == *"Object is WORM protected and cannot be overwritten"* ]] || fail "unexpected error message: $error"

  delete_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error deleting object"
  delete_bucket_recursive "s3api" "$BUCKET_ONE_NAME"
}

legal_hold_retention_setup() {
  [[ $# -eq 3 ]] || fail "legal hold or retention setup requires username, secret key, bucket file"

  delete_bucket_or_contents_if_exists "s3api" "$BUCKET_ONE_NAME" || fail "error deleting bucket, or checking for existence"
  setup_user "$1" "$2" "user" || fail "error creating user if nonexistent"
  create_test_files "$3" || fail "error creating test files"

  #create_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error creating bucket"
  create_bucket_object_lock_enabled "$BUCKET_ONE_NAME" || fail "error creating bucket"
  change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$BUCKET_ONE_NAME" "$1" || fail "error changing bucket ownership"
  get_bucket_policy "s3api" "$BUCKET_ONE_NAME" || fail "error getting bucket policy"
  # shellcheck disable=SC2154
  log 5 "POLICY: $bucket_policy"
  get_bucket_owner "$BUCKET_ONE_NAME"
  # shellcheck disable=SC2154
  log 5 "owner: $bucket_owner"
  #put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred" || fail "error putting bucket ownership controls"
  put_object_with_user "s3api" "$test_file_folder/$3" "$BUCKET_ONE_NAME" "$3" "$1" "$2" || fail "failed to add object to bucket"
}

test_s3api_list_objects_v1_aws_root() {
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

  list_objects_s3api_v1 "$BUCKET_ONE_NAME"
  # shellcheck disable=SC2154
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

test_s3api_list_objects_v2_aws_root() {
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

test_multipart_upload_list_parts_aws_root() {
  local bucket_file="bucket-file"

  create_test_files "$bucket_file" || fail "error creating test file"
  dd if=/dev/urandom of="$test_file_folder/$bucket_file" bs=5M count=1 || fail "error creating test file"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "failed to create bucket '$BUCKET_ONE_NAME'"

  list_parts "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || fail "listing multipart upload parts failed"

  declare -a parts_map
  # shellcheck disable=SC2154
  log 5 "parts: $parts"
  for i in {0..3}; do
    local part_number
    local etag
    # shellcheck disable=SC2154
    part=$(echo "$parts" | grep -v "InsecureRequestWarning" | jq -r ".[$i]" 2>&1) || fail "error getting part: $part"
    part_number=$(echo "$part" | jq ".PartNumber" 2>&1) || fail "error parsing part number: $part_number"
    [[ $part_number != "" ]] || fail "error:  blank part number"

    etag=$(echo "$part" | jq ".ETag" 2>&1) || fail "error parsing etag: $etag"
    [[ $etag != "" ]] || fail "error:  blank etag"
    # shellcheck disable=SC2004
    parts_map[$part_number]=$etag
  done
  [[ ${#parts_map[@]} -ne 0 ]] || fail "error loading multipart upload parts to check"

  for i in {0..3}; do
    local part_number
    local etag
    # shellcheck disable=SC2154
    listed_part=$(echo "$listed_parts" | grep -v "InsecureRequestWarning" | jq -r ".Parts[$i]" 2>&1) || fail "error parsing listed part: $listed_part"
    part_number=$(echo "$listed_part" | jq ".PartNumber" 2>&1) || fail "error parsing listed part number: $part_number"
    etag=$(echo "$listed_part" | jq ".ETag" 2>&1) || fail "error getting listed etag: $etag"
    [[ ${parts_map[$part_number]} == "$etag" ]] || fail "error:  etags don't match (part number: $part_number, etags ${parts_map[$part_number]},$etag)"
  done

  run_then_abort_multipart_upload "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder/$bucket_file" 4
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}
