#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_aws.sh
source ./tests/util_bucket_create.sh
source ./tests/util_file.sh
source ./tests/util_users.sh
source ./tests/test_aws_root_inner.sh
source ./tests/test_common.sh
source ./tests/commands/copy_object.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/get_bucket_versioning.sh
source ./tests/commands/get_object.sh
source ./tests/commands/get_object_attributes.sh
source ./tests/commands/get_object_legal_hold.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/get_object_retention.sh
source ./tests/commands/get_object_tagging.sh
source ./tests/commands/list_multipart_uploads.sh
source ./tests/commands/list_object_versions.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_policy.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object.sh
source ./tests/commands/put_object_legal_hold.sh
source ./tests/commands/put_object_lock_configuration.sh
source ./tests/commands/put_object_retention.sh
source ./tests/commands/put_public_access_block.sh
source ./tests/commands/select_object_content.sh

export RUN_USERS=true

# abort-multipart-upload
@test "test_abort_multipart_upload" {
  test_abort_multipart_upload_aws_root
}

# complete-multipart-upload
@test "test_complete_multipart_upload" {
  test_complete_multipart_upload_aws_root
}

# copy-object
@test "test_copy_object" {
  test_common_copy_object "s3api"
}

@test "test_copy_object_empty" {
  copy_object_empty || fail "copy objects with no parameters test failure"
}

# create-bucket
@test "test_create_delete_bucket_aws" {
  test_common_create_delete_bucket "aws"
}

@test "test_create_bucket_invalid_name" {
  test_create_bucket_invalid_name_aws_root
}

# create-multipart-upload
@test "test_create_multipart_upload_properties" {
  test_create_multipart_upload_properties_aws_root
}

# delete-bucket - test_create_delete_bucket_aws

# delete-bucket-policy
@test "test_get_put_delete_bucket_policy" {
  test_common_get_put_delete_bucket_policy "aws"
}

# delete-bucket-tagging
@test "test-set-get-delete-bucket-tags" {
  test_common_set_get_delete_bucket_tags "aws"
}

# delete-object - tested with bucket cleanup before or after tests

# delete-object-tagging
@test "test_delete_object_tagging" {
  test_common_delete_object_tagging "aws"
}

# delete-objects
@test "test_delete_objects" {
  test_delete_objects_aws_root
}

# get-bucket-acl
@test "test_get_bucket_acl" {
  test_get_bucket_acl_aws_root
}

# get-bucket-location
@test "test_get_bucket_location" {
  test_common_get_bucket_location "aws"
}

# get-bucket-policy - test_get_put_delete_bucket_policy

# get-bucket-tagging - test_set_get_delete_bucket_tags

# get-object
@test "test_get_object_full_range" {
  test_get_object_full_range_aws_root
}

@test "test_get_object_invalid_range" {
  test_get_object_invalid_range_aws_root
}

# get-object-attributes
@test "test_get_object_attributes" {
  test_get_object_attributes_aws_root
}

@test "test_put_object" {
  test_put_object_aws_root
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

@test "test_get_put_object_legal_hold" {
  test_get_put_object_legal_hold_aws_root
}

@test "test_get_put_object_retention" {
  test_get_put_object_retention_aws_root
}

@test "test_put_bucket_acl" {
  test_common_put_bucket_acl "s3api"
}

# test v1 s3api list objects command
@test "test-s3api-list-objects-v1" {
  test_s3api_list_objects_v1_aws_root
}

# test v2 s3api list objects command
@test "test-s3api-list-objects-v2" {
  test_s3api_list_objects_v2_aws_root
}

# test abilty to set and retrieve object tags
@test "test-set-get-object-tags" {
  test_common_set_get_object_tags "aws"
}

# test multi-part upload list parts command
@test "test-multipart-upload-list-parts" {
  test_multipart_upload_list_parts_aws_root
}

# test listing of active uploads
@test "test-multipart-upload-list-uploads" {
  local bucket_file_one="bucket-file-one"
  local bucket_file_two="bucket-file-two"

  if [[ $RECREATE_BUCKETS == false ]]; then
    abort_all_multipart_uploads "$BUCKET_ONE_NAME" || fail "error aborting all uploads"
  fi

  create_test_files "$bucket_file_one" "$bucket_file_two" || fail "error creating test files"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "failed to create bucket '$BUCKET_ONE_NAME'"

  create_and_list_multipart_uploads "$BUCKET_ONE_NAME" "$test_file_folder"/"$bucket_file_one" "$test_file_folder"/"$bucket_file_two" || fail "failed to list multipart uploads"

  local key_one
  local key_two
  # shellcheck disable=SC2154
  log 5 "Uploads:  $uploads"
  raw_uploads=$(echo "$uploads" | grep -v "InsecureRequestWarning")
  key_one=$(echo "$raw_uploads" | jq -r '.Uploads[0].Key' 2>&1) || fail "error getting key one: $key_one"
  key_two=$(echo "$raw_uploads" | jq -r '.Uploads[1].Key' 2>&1) || fail "error getting key two: $key_two"
  key_one=${key_one//\"/}
  key_two=${key_two//\"/}
  [[ "$test_file_folder/$bucket_file_one" == *"$key_one" ]] || fail "Key mismatch ($test_file_folder/$bucket_file_one, $key_one)"
  [[ "$test_file_folder/$bucket_file_two" == *"$key_two" ]] || fail "Key mismatch ($test_file_folder/$bucket_file_two, $key_two)"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$bucket_file_one" "$bucket_file_two"
}

@test "test-multipart-upload-from-bucket" {
  local bucket_file="bucket-file"

  create_test_files "$bucket_file" || fail "error creating test files"
  dd if=/dev/urandom of="$test_file_folder/$bucket_file" bs=5M count=1 || fail "error adding data to test file"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "failed to create bucket: $BUCKET_ONE_NAME"

  multipart_upload_from_bucket "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 || fail "error performing multipart upload"

  get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file-copy" "$test_file_folder/$bucket_file-copy" || fail "error getting object"
  compare_files "$test_file_folder"/$bucket_file-copy "$test_file_folder"/$bucket_file || fail "data doesn't match"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

@test "test_multipart_upload_from_bucket_range_too_large" {
  local bucket_file="bucket-file"

  create_large_file "$bucket_file" || error creating file "$bucket_file"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  multipart_upload_from_bucket_range "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 "bytes=0-1000000000" || local upload_result=$?
  [[ $upload_result -eq 1 ]] || fail "multipart upload with overly large range should have failed"
  log 5 "error: $upload_part_copy_error"
  [[ $upload_part_copy_error == *"Range specified is not valid"* ]] || [[ $upload_part_copy_error == *"InvalidRange"* ]] || fail "unexpected error: $upload_part_copy_error"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

@test "test_multipart_upload_from_bucket_range_valid" {
  local bucket_file="bucket-file"

  create_large_file "$bucket_file" || error creating file "$bucket_file"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  range_max=$((5*1024*1024-1))
  multipart_upload_from_bucket_range "$BUCKET_ONE_NAME" "$bucket_file" "$test_file_folder"/"$bucket_file" 4 "bytes=0-$range_max" || fail "upload failure"

  get_object "s3api" "$BUCKET_ONE_NAME" "$bucket_file-copy" "$test_file_folder/$bucket_file-copy" || fail "error retrieving object after upload"
  if [[ $(uname) == 'Darwin' ]]; then
    object_size=$(stat -f%z "$test_file_folder/$bucket_file-copy")
  else
    object_size=$(stat --format=%s "$test_file_folder/$bucket_file-copy")
  fi
  [[ object_size -eq $((range_max*4+4)) ]] || fail "object size mismatch ($object_size, $((range_max*4+4)))"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

@test "test-presigned-url-utf8-chars" {
  test_common_presigned_url_utf8_chars "aws"
}

@test "test-list-objects-delimiter" {
  folder_name="two"
  object_name="three"
  create_test_folder "$folder_name" || fail "error creating folder"
  create_test_files "$folder_name"/"$object_name" || fail "error creating file"

  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "error setting up bucket"

  put_object "aws" "$test_file_folder/$folder_name/$object_name" "$BUCKET_ONE_NAME" "$folder_name/$object_name" || fail "failed to add object to bucket"

  list_objects_s3api_v1 "$BUCKET_ONE_NAME" "/"
  prefix=$(echo "${objects[@]}" | jq -r ".CommonPrefixes[0].Prefix" 2>&1) || fail "error getting object prefix from object list: $prefix"
  [[ $prefix == "$folder_name/" ]] || fail "prefix doesn't match (expected $prefix, actual $folder_name/)"

  list_objects_s3api_v1 "$BUCKET_ONE_NAME" "#"
  key=$(echo "${objects[@]}" | jq -r ".Contents[0].Key" 2>&1) || fail "error getting key from object list: $key"
  [[ $key == "$folder_name/$object_name" ]] || fail "key doesn't match (expected $key, actual $folder_name/$object_name)"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files $folder_name
}

#@test "test_put_policy_no_version" {
#  policy_file="policy_file"
#
#  create_test_files "$policy_file" || fail "error creating policy file"
#
#  effect="Allow"
#  principal="*"
#  action="s3:GetObject"
#  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"
#
#  cat <<EOF > "$test_file_folder"/$policy_file
#    {
#      "Statement": [
#        {
#           "Effect": "$effect",
#           "Principal": "$principal",
#           "Action": "$action",
#           "Resource": "$resource"
#        }
#      ]
#    }
#EOF
#
#    setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
#
#    check_for_empty_policy "s3api" "$BUCKET_ONE_NAME" || fail "policy not empty"
#
#    put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
#
#    get_bucket_policy "s3api" "$BUCKET_ONE_NAME" || fail "unable to retrieve policy"
#}

@test "test_put_policy_invalid_action" {
  policy_file="policy_file"

  create_test_files "$policy_file" || fail "error creating policy file"

  effect="Allow"
  principal="*"
  action="s3:GetObjectt"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"

  cat <<EOF > "$test_file_folder"/$policy_file
    {
      "Statement": [
        {
           "Effect": "$effect",
           "Principal": "$principal",
           "Action": "$action",
           "Resource": "$resource"
        }
      ]
    }
EOF

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"

  check_for_empty_policy "s3api" "$BUCKET_ONE_NAME" || fail "policy not empty"

  if put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file"; then
    fail "put succeeded despite malformed policy"
  fi
  # shellcheck disable=SC2154
  [[ "$put_bucket_policy_error" == *"MalformedPolicy"*"invalid action"* ]] || fail "invalid policy error: $put_bucket_policy_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file"
}

@test "test_policy_get_object_with_user" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi

  policy_file="policy_file"
  username="ABCDEFG"
  password="HIJKLMN"
  test_file="test_file"

  create_test_files "$test_file" "$policy_file" || fail "error creating policy file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"

  setup_policy_with_single_statement "$test_file_folder/$policy_file" "2012-10-17" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "error copying object"

  if ! check_for_empty_policy "s3api" "$BUCKET_ONE_NAME"; then
    delete_bucket_policy "s3api" "$BUCKET_ONE_NAME" || fail "error deleting policy"
    check_for_empty_policy "s3api" "$BUCKET_ONE_NAME" || fail "policy not empty after deletion"
  fi

  setup_user "$username" "$password" "user" || fail "error creating user"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password"; then
    fail "get object with user succeeded despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error getting object after permissions"
  compare_files "$test_file_folder/$test_file" "$test_file_folder/$test_file-copy" || fail "files not equal"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

@test "test_policy_get_object_specific_file" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi

  policy_file="policy_file"
  test_file="test_file"
  test_file_two="test_file_two"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" "$test_file" "$test_file_two" || fail "error creating policy file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file"
  echo "$BATS_TEST_NAME-2" >> "$test_file_folder/$test_file_two"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/test_file"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "error copying object"
  put_object "s3api" "$test_file_folder/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object"

  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error getting object after permissions"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$test_file_folder/$test_file_two-copy" "$username" "$password"; then
    fail "get object with user succeeded despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

@test "test_policy_get_object_file_wildcard" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi

  policy_file="policy_file_one"
  policy_file_two="policy_file_two"
  policy_file_three="policy_fil"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" "$policy_file_two" "$policy_file_three" || fail "error creating policy file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$policy_file"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/policy_file*"

  setup_user "$username" "$password" "user" || fail "error creating user account"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$policy_file" "$BUCKET_ONE_NAME" "$policy_file" || fail "error copying object one"
  put_object "s3api" "$test_file_folder/$policy_file_two" "$BUCKET_ONE_NAME" "$policy_file_two" || fail "error copying object two"
  put_object "s3api" "$test_file_folder/$policy_file_three" "$BUCKET_ONE_NAME" "$policy_file_three" || fail "error copying object three"

  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$policy_file" "$test_file_folder/$policy_file" "$username" "$password" || fail "error getting object one after permissions"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$policy_file_two" "$test_file_folder/$policy_file_two" "$username" "$password" || fail "error getting object two after permissions"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$policy_file_three" "$test_file_folder/$policy_file_three" "$username" "$password"; then
    fail "get object three with user succeeded despite lack of permissions"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

@test "test_policy_get_object_folder_wildcard" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi

  policy_file="policy_file"
  test_folder="test_folder"
  test_file="test_file"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_folder "$test_folder" || fail "error creating test folder"
  create_test_files "$test_folder/$test_file" "$policy_file" || fail "error creating policy file, test file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_folder/$test_file"

  effect="Allow"
  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" || fail "error copying object to bucket"

  download_and_compare_file_with_user "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_file_folder/$test_file-copy" "$username" "$password" || fail "error downloading and comparing file"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_folder/$test_file" "$policy_file"
}

@test "test_policy_allow_deny" {
  policy_file="policy_file"
  test_file="test_file"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" "$test_file" || fail "error creating policy file"

  principal="$username"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file"

  cat <<EOF > "$test_file_folder"/$policy_file
    {
      "Statement": [
        {
           "Effect": "Deny",
           "Principal": "$principal",
           "Action": "$action",
           "Resource": "$resource"
        },
        {
           "Effect": "Allow",
           "Principal": "$principal",
           "Action": "$action",
           "Resource": "$resource"
        }
      ]
    }
EOF

  setup_user "$username" "$password" "user" || fail "error creating user"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  put_object "s3api" "$test_file_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" || fail "error copying object to bucket"

  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file" "$test_file_folder/$test_file-copy" "$username" "$password"; then
    fail "able to get object despite deny statement"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file" "$test_file-copy" "$policy_file"
}

@test "test_policy_deny" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi

  policy_file="policy_file"
  test_file_one="test_file_one"
  test_file_two="test_file_two"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$test_file_one" "$test_file_two" "$policy_file" || fail "error creating policy file, test file"

  cat <<EOF > "$test_file_folder"/$policy_file
{
  "Statement": [
    {
       "Effect": "Deny",
       "Principal": "$username",
       "Action": "s3:GetObject",
       "Resource": "arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two"
    },
    {
       "Effect": "Allow",
       "Principal": "$username",
       "Action": "s3:GetObject",
       "Resource": "arn:aws:s3:::$BUCKET_ONE_NAME/*"
    }
  ]
}
EOF

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  log 5 "Policy: $(cat "$test_file_folder/$policy_file")"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  put_object "s3api" "$test_file_folder/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one" || fail "error copying object one"
  put_object "s3api" "$test_file_folder/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object two"
  get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_one" "$test_file_folder/$test_file_one-copy" "$username" "$password" || fail "error getting object"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$test_file_folder/$test_file_two-copy" "$username" "$password"; then
    fail "able to get object despite deny statement"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file_one" "$test_file_two" "$test_file_one-copy" "$test_file_two-copy" "$policy_file"
}

@test "test_policy_put_wildcard" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi

  policy_file="policy_file"
  test_folder="test_folder"
  test_file="test_file"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_folder "$test_folder" || fail "error creating test folder"
  create_test_files "$test_folder/$test_file" "$policy_file" || fail "error creating policy file, test file"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_folder/$test_file"

  effect="Allow"
  principal="$username"
  action="s3:PutObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_folder/*"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  log 5 "Policy: $(cat "$test_file_folder/$policy_file")"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  if put_object_with_user "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_file" "$username" "$password"; then
    fail "able to put object despite not being allowed"
  fi
  [[ "$put_object_error" == *"Access Denied"* ]] || fail "invalid put object error: $put_object_error"
  put_object_with_user "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$username" "$password" || fail "error putting file despite policy permissions"
  if get_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_folder/$test_file-copy" "$username" "$password"; then
    fail "able to get object without permissions"
  fi
  [[ "$get_object_error" == *"Access Denied"* ]] || fail "invalid get object error: $get_object_error"
  download_and_compare_file "s3api" "$test_file_folder/$test_folder/$test_file" "$BUCKET_ONE_NAME" "$test_folder/$test_file" "$test_file_folder/$test_file-copy" || fail "files don't match"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_folder/$test_file" "$test_file-copy" "$policy_file"
}

@test "test_policy_delete" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi
  policy_file="policy_file"
  test_file_one="test_file_one"
  test_file_two="test_file_two"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$test_file_one" "$test_file_two" "$policy_file" || fail "error creating policy file, test files"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file_one"
  echo "$BATS_TEST_NAME" >> "$test_file_folder/$test_file_two"

  effect="Allow"
  principal="$username"
  action="s3:DeleteObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/$test_file_two"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  log 5 "Policy: $(cat "$test_file_folder/$policy_file")"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"

  put_object "s3api" "$test_file_folder/$test_file_one" "$BUCKET_ONE_NAME" "$test_file_one" || fail "error copying object one"
  put_object "s3api" "$test_file_folder/$test_file_two" "$BUCKET_ONE_NAME" "$test_file_two" || fail "error copying object two"
  if delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_one" "$username" "$password"; then
    fail "able to delete object despite lack of permissions"
  fi
  [[ "$delete_object_error" == *"Access Denied"* ]] || fail "invalid delete object error: $delete_object_error"
  delete_object_with_user "s3api" "$BUCKET_ONE_NAME" "$test_file_two" "$username" "$password" || fail "error deleting object despite permissions"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file_one" "$test_file_two" "$policy_file"
}

@test "test_policy_get_bucket_policy" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi
  policy_file="policy_file"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:GetBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  if get_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "able to retrieve bucket policy despite lack of permissions"
  fi

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  get_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error getting bucket policy despite permissions"
  # shellcheck disable=SC2154
  echo "$bucket_policy" > "$test_file_folder/$policy_file-copy"
  log 5 "ORIG: $(cat "$test_file_folder/$policy_file")"
  log 5 "COPY: $(cat "$test_file_folder/$policy_file-copy")"
  compare_files "$test_file_folder/$policy_file" "$test_file_folder/$policy_file-copy" || fail "policies not equal"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$policy_file-copy"
}

@test "test_policy_list_multipart_uploads" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi
  policy_file="policy_file"
  test_file="test_file"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" || fail "error creating policy file, test files"
  create_large_file "$test_file" || error creating file "$test_file"

  effect="Allow"
  principal="$username"
  action="s3:ListBucketMultipartUploads"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  create_multipart_upload "$BUCKET_ONE_NAME" "$test_file" || fail "error creating multipart upload"
  if list_multipart_uploads_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    log 2 "able to list multipart uploads despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$list_multipart_uploads_error" == *"Access Denied"* ]] || fail "invalid list multipart uploads error: $list_multipart_uploads_error"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  list_multipart_uploads_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error listing multipart uploads"
  log 5 "$uploads"
  upload_key=$(echo "$uploads" | grep -v "InsecureRequestWarning" | jq -r ".Uploads[0].Key" 2>&1) || fail "error parsing upload key from uploads message: $upload_key"
  [[ $upload_key == "$test_file" ]] || fail "upload key doesn't match file marked as being uploaded"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$test_file"
}

@test "test_policy_put_bucket_policy" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi
  policy_file="policy_file"
  policy_file_two="policy_file_two"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:PutBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  if put_bucket_policy_with_user "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" "$username" "$password"; then
    fail "able to retrieve bucket policy despite lack of permissions"
  fi

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  setup_policy_with_single_statement "$test_file_folder/$policy_file_two" "dummy" "$effect" "$principal" "s3:GetBucketPolicy" "$resource" || fail "failed to set up policy"
  put_bucket_policy_with_user "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file_two" "$username" "$password" || fail "error putting bucket policy despite permissions"
  get_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error getting bucket policy despite permissions"
  # shellcheck disable=SC2154
  echo "$bucket_policy" > "$test_file_folder/$policy_file-copy"
  log 5 "ORIG: $(cat "$test_file_folder/$policy_file_two")"
  log 5 "COPY: $(cat "$test_file_folder/$policy_file-copy")"
  compare_files "$test_file_folder/$policy_file_two" "$test_file_folder/$policy_file-copy" || fail "policies not equal"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$policy_file_two" "$policy_file-copy"
}

@test "test_policy_delete_bucket_policy" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi
  policy_file="policy_file"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:DeleteBucketPolicy"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  if delete_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "able to delete bucket policy with user $username without right permissions"
  fi
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  delete_bucket_policy_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "unable to delete bucket policy"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file"
}

@test "test_policy_get_bucket_acl" {
  # TODO (https://github.com/versity/versitygw/issues/637)
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    return 0
  fi
  policy_file="policy_file"
  username="ABCDEFG"
  password="HIJKLMN"

  create_test_files "$policy_file" || fail "error creating policy file, test files"

  effect="Allow"
  principal="$username"
  action="s3:GetBucketAcl"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME"

  setup_user "$username" "$password" "user" || fail "error creating user"

  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  #put_bucket_canned_acl "$BUCKET_ONE_NAME" "private" || fail "error putting bucket canned ACL"
  if get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password"; then
    fail "user able to get bucket ACLs despite permissions"
  fi
  setup_policy_with_single_statement "$test_file_folder/$policy_file" "dummy" "$effect" "$principal" "$action" "$resource" || fail "failed to set up policy"
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  get_bucket_acl_with_user "$BUCKET_ONE_NAME" "$username" "$password" || fail "error getting bucket ACL despite permissions"
}

# ensure that lists of files greater than a size of 1000 (pagination) are returned properly
#@test "test_list_objects_file_count" {
#  test_common_list_objects_file_count "aws"
#}

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
  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  head_bucket "aws" "$BUCKET_ONE_NAME" || fail "error getting bucket info"
  log 5 "INFO:  $bucket_info"
  region=$(echo "$bucket_info" | grep -v "InsecureRequestWarning" | jq -r ".BucketRegion" 2>&1) || fail "error getting bucket region: $region"
  [[ $region != "" ]] || fail "empty bucket region"
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

@test "test_head_bucket_invalid_name" {
  if head_bucket "aws" ""; then
    fail "able to get bucket info for invalid name"
  fi
}

@test "test_retention_bypass" {
  test_retention_bypass_aws_root
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

  create_test_files "$object_one" || fail "error creating test files"

  setup_bucket "aws" "$BUCKET_ONE_NAME" || fail "error setting up bucket"

  object="$test_file_folder"/"$object_one"
  put_object_with_metadata "aws" "$object" "$BUCKET_ONE_NAME" "$object_one" "$test_key" "$test_value" || fail "failed to add object to bucket"
  object_exists "aws" "$BUCKET_ONE_NAME" "$object_one" || fail "object not found after being added to bucket"

  get_object_metadata "aws" "$BUCKET_ONE_NAME" "$object_one" || fail "error getting object metadata"
  key=$(echo "$metadata" | jq -r 'keys[]' 2>&1) || fail "error getting key from metadata: $key"
  value=$(echo "$metadata" | jq -r '.[]' 2>&1) || fail "error getting value from metadata: $value"
  [[ $key == "$test_key" ]] || fail "keys doesn't match (expected $key, actual \"$test_key\")"
  [[ $value == "$test_value" ]] || fail "values doesn't match (expected $value, actual \"$test_value\")"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$object_one"
}

@test "test_policy_abort_multipart_upload" {
  policy_file="policy_file"
  test_file="test_file"
  username="ABCDEFG"

  create_test_files "$policy_file" || fail "error creating policy file"
  create_large_file "$test_file" || fail "error creating large file"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"
  if [[ $DIRECT == "true" ]]; then
    setup_user_direct "$username" "user" "$BUCKET_ONE_NAME" || fail "error setting up direct user $username"
    principal="{\"AWS\": \"arn:aws:iam::$DIRECT_AWS_USER_ID:user/$username\"}"
    # shellcheck disable=SC2154
    username=$key_id
    # shellcheck disable=SC2154
    password=$secret_key
  else
    password="HIJLKMN"
    setup_user "$username" "$password" "user" || fail "error setting up user $username"
    principal="\"$username\""
  fi

  cat <<EOF > "$test_file_folder"/$policy_file
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": $principal,
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$BUCKET_ONE_NAME/*"
    },
    {
      "Effect": "Deny",
      "Principal": $principal,
      "Action": "s3:AbortMultipartUpload",
      "Resource": "arn:aws:s3:::$BUCKET_ONE_NAME/*"
    }
  ]
}
EOF
  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting first policy"

  create_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$username" "$password" || fail "error creating multipart upload"
  if abort_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password"; then
    fail "abort multipart upload succeeded despite lack of permissions"
  fi
  # shellcheck disable=SC2154
  [[ "$abort_multipart_upload_error" == *"AccessDenied"* ]] || fail "unexpected abort error:  $abort_multipart_upload_error"

  cat <<EOF > "$test_file_folder"/$policy_file
{
  "Version": "2012-10-17",
  "Statement": [
    {
       "Effect": "Allow",
       "Principal": $principal,
       "Action": "s3:AbortMultipartUpload",
       "Resource": "arn:aws:s3:::$BUCKET_ONE_NAME/*"
    }
  ]
}
EOF

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  abort_multipart_upload_with_user "$BUCKET_ONE_NAME" "$test_file" "$upload_id" "$username" "$password" || fail "error aborting multipart upload despite permissions"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$policy_file" "$test_file"
}

@test "test_policy_put_acl" {
  if [[ $DIRECT != "true" ]]; then
    # https://github.com/versity/versitygw/issues/702
    skip
  fi

  policy_file="policy_file"
  test_file="test_file"
  username="ABCDEFG"
  password="HIJLKMN"

  create_test_files "$policy_file" || fail "error creating policy file"
  create_large_file "$test_file" || fail "error creating large file"
  setup_bucket "s3api" "$BUCKET_ONE_NAME" || fail "error setting up bucket"

  put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred" || fail "error putting bucket ownership controls"

  if [[ $DIRECT == "true" ]]; then
    setup_user_direct "$username" "user" "$BUCKET_ONE_NAME" || fail "error setting up direct user $username"
    principal="{\"AWS\": \"arn:aws:iam::$DIRECT_AWS_USER_ID:user/$username\"}"
    # shellcheck disable=SC2154
    username=$key_id
    # shellcheck disable=SC2154
    password=$secret_key
  else
    password="HIJLKMN"
    setup_user "$username" "$password" "user" || fail "error setting up user $username"
    principal="\"$username\""
  fi

  cat <<EOF > "$test_file_folder"/$policy_file
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": $principal,
      "Action": "s3:PutBucketAcl",
      "Resource": "arn:aws:s3:::$BUCKET_ONE_NAME"
    }
  ]
}
EOF
  if [[ $DIRECT == "true" ]]; then
    put_public_access_block_enable_public_acls "$BUCKET_ONE_NAME" || fail "error enabling public ACLs"
  fi

  put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$policy_file" || fail "error putting policy"
  put_bucket_canned_acl_with_user "$BUCKET_ONE_NAME" "public-read" "$username" "$password" || fail "error putting canned acl"

  get_bucket_acl "s3api" "$BUCKET_ONE_NAME" || fail "error getting bucket acl"
  # shellcheck disable=SC2154
  log 5 "ACL: $acl"
  second_grant=$(echo "$acl" | jq -r ".Grants[1]" 2>&1) || fail "error getting second grant: $second_grant"
  second_grantee=$(echo "$second_grant" | jq -r ".Grantee" 2>&1) || fail "error getting second grantee: $second_grantee"
  permission=$(echo "$second_grant" | jq -r ".Permission" 2>&1) || fail "error getting permission: $permission"
  log 5 "second grantee: $second_grantee"
  [[ $permission == "READ" ]] || fail "incorrect permission: $permission"
  if [[ $DIRECT == "true" ]]; then
    uri=$(echo "$second_grantee" | jq -r ".URI" 2>&1) || fail "error getting uri: $uri"
    [[ $uri == "http://acs.amazonaws.com/groups/global/AllUsers" ]] || fail "unexpected URI: $uri"
  else
    id=$(echo "$second_grantee" | jq -r ".ID" 2>&1) || fail "error getting ID: $id"
    [[ $id == "$username" ]] || fail "unexpected ID: $id"
  fi
  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
}

@test "test_put_object_lock_configuration" {
  bucket_name=$BUCKET_ONE_NAME
  if [[ $RECREATE_BUCKETS == "true" ]]; then
    delete_bucket "s3api" "$bucket_name" || fail "error deleting bucket"
    create_bucket_object_lock_enabled "$bucket_name" || fail "error setting up bucket"
  fi
  local enabled="Enabled"
  local governance="GOVERNANCE"
  local days="1"
  put_object_lock_configuration "$bucket_name" "$enabled" "$governance" "$days" || fail "error putting object lock configuration"

  get_object_lock_configuration "$bucket_name" || fail "error getting object lock configuration"
  log 5 "LOCK CONFIG: $lock_config"
  object_lock_configuration=$(echo "$lock_config" | jq -r ".ObjectLockConfiguration" 2>&1) || fail "error getting ObjectLockConfiguration: $object_lock_configuration"
  object_lock_enabled=$(echo "$object_lock_configuration" | jq -r ".ObjectLockEnabled" 2>&1) || fail "error getting ObjectLockEnabled: $object_lock_enabled"
  [[ $object_lock_enabled == "$enabled" ]] || fail "incorrect ObjectLockEnabled value: $object_lock_enabled"
  default_retention=$(echo "$object_lock_configuration" | jq -r ".Rule.DefaultRetention" 2>&1) || fail "error getting DefaultRetention: $default_retention"
  mode=$(echo "$default_retention" | jq -r ".Mode" 2>&1) || fail "error getting Mode: $mode"
  [[ $mode == "$governance" ]] || fail "incorrect Mode value: $mode"
  returned_days=$(echo "$default_retention" | jq -r ".Days" 2>&1) || fail "error getting Days: $returned_days"
  [[ $returned_days == "1" ]] || fail "incorrect Days value: $returned_days"
  delete_bucket_or_contents "aws" "$bucket_name"
}
