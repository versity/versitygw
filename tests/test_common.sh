#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_file.sh
source ./tests/util_policy.sh
source ./tests/commands/copy_object.sh
source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_location.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/get_object.sh
source ./tests/commands/list_buckets.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_object.sh

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

  put_object "$1" "$test_file_folder/$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || local put_result=$?
  [[ $put_result -eq 0 ]] || fail "failed to copy file"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files $bucket_file
}

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

test_common_copy_object() {
  if [[ $# -ne 1 ]]; then
    fail "copy object test requires command type"
  fi
  local object_name="test-object"
  create_test_files "$object_name" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Error creating test file"
  echo "test data" > "$test_file_folder/$object_name"

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket one"
  setup_bucket "$1" "$BUCKET_TWO_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket two"

  if [[ $1 == 's3' ]]; then
    copy_object "$1" "$test_file_folder/$object_name" "$BUCKET_ONE_NAME" "$object_name" || local put_result=$?
  else
    put_object "$1" "$test_file_folder/$object_name" "$BUCKET_ONE_NAME" "$object_name" || local put_result=$?
  fi
  [[ $put_result -eq 0 ]] || fail "Failed to add object to bucket"
  if [[ $1 == 's3' ]]; then
    copy_object "$1" "s3://$BUCKET_ONE_NAME/$object_name" "$BUCKET_TWO_NAME" "$object_name" || local copy_result_one=$?
  else
    copy_object "$1" "$BUCKET_ONE_NAME/$object_name" "$BUCKET_TWO_NAME" "$object_name" || local copy_result_one=$?
  fi
  [[ $copy_result_one -eq 0 ]] || fail "Object not added to bucket"
  get_object "$1" "$BUCKET_TWO_NAME" "$object_name" "$test_file_folder/$object_name-copy" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "failed to retrieve object"

  compare_files "$test_file_folder/$object_name" "$test_file_folder/$object_name-copy" || local compare_result=$?
  [[ $compare_result -eq 0 ]] || fail "files not the same"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_bucket_or_contents "$1" "$BUCKET_TWO_NAME"
}

test_common_put_object_with_data() {
  if [[ $# -ne 1 ]]; then
    fail "put object test requires command type"
  fi

  local object_name="test-object"
  create_test_files "$object_name" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Error creating test file"
  echo "test data" > "$test_file_folder"/"$object_name"
  test_common_put_object "$1" "$object_name"
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

  put_object "$1" "$test_file_folder/$2" "$BUCKET_ONE_NAME" "$2" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"
  object_exists "$1" "$BUCKET_ONE_NAME" "$2" || local exists_result_one=$?
  [[ $exists_result_one -eq 0 ]] || fail "Object not added to bucket"

  delete_object "$1" "$BUCKET_ONE_NAME" "$2" || local delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "Failed to delete object"
  object_exists "$1" "$BUCKET_ONE_NAME" "$2" || local exists_result_two=$?
  [[ $exists_result_two -eq 1 ]] || fail "Object not removed from bucket"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files "$2"
}

test_common_put_get_object() {
  if [[ $# -ne 1 ]]; then
    fail "put, get object test requires command type"
  fi

  local object_name="test-object"
  create_test_files "$object_name" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Error creating test file"
  echo "test data" > "$test_file_folder"/"$object_name"

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  put_object "$1" "$test_file_folder/$object_name" "$BUCKET_ONE_NAME" "$object_name" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"
  object_exists "$1" "$BUCKET_ONE_NAME" "$object_name" || local exists_result_one=$?
  [[ $exists_result_one -eq 0 ]] || fail "Object not added to bucket"

  get_object "$1" "$BUCKET_ONE_NAME" "$object_name" "$test_file_folder/${object_name}_copy" || local delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "Failed to delete object"
  object_exists "$1" "$BUCKET_ONE_NAME" "$object_name" || local exists_result_two=$?
  [[ $exists_result_two -eq 1 ]] || fail "Object not removed from bucket"

  compare_files "$test_file_folder"/"$object_name" "$test_file_folder/${object_name}_copy" || compare_result=$?
  [[ $compare_result -ne 0 ]] || fail "objects are different"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files "$test_file_folder/$object_name" "$test_file_folder/${object_name}_copy"
}

test_common_get_set_versioning() {
  local object_name="test-object"
  create_test_files "$object_name" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Error creating test file"

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  get_bucket_versioning "$1" "$BUCKET_ONE_NAME" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "error getting bucket versioning"

  put_bucket_versioning "$1" "$BUCKET_ONE_NAME" "Enabled" || local put_result=$?
  [[ $put_result -eq 0 ]] || fail "error putting bucket versioning"

  get_bucket_versioning "$1" "$BUCKET_ONE_NAME" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "error getting bucket versioning"

  fail "test fail"
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
  log 5 "bucket array: ${bucket_array[*]}"
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
  put_object "$1" "$test_file_folder"/$object_one "$BUCKET_ONE_NAME" "$object_one"  || local result_two=$?
  [[ result_two -eq 0 ]] || fail "Error adding object one"
  put_object "$1" "$test_file_folder"/$object_two "$BUCKET_ONE_NAME" "$object_two" || local result_three=$?
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

test_common_set_get_delete_bucket_tags() {
  if [[ $# -ne 1 ]]; then
    fail "set/get bucket tags test requires command type"
  fi

  local key="test_key"
  local value="test_value"

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"

  get_bucket_tagging "$1" "$BUCKET_ONE_NAME" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "Error getting bucket tags first time"

  check_bucket_tags_empty "$1" "$BUCKET_ONE_NAME" || local check_result=$?
  [[ $check_result -eq 0 ]] || fail "error checking if bucket tags are empty"

  put_bucket_tag "$1" "$BUCKET_ONE_NAME" $key $value
  get_bucket_tagging "$1" "$BUCKET_ONE_NAME" || local get_result_two=$?
  [[ $get_result_two -eq 0 ]] || fail "Error getting bucket tags second time"

  local tag_set_key
  local tag_set_value
  if [[ $1 == 'aws' ]]; then
    log 5 "Post-export tags: $tags"
    tag_set_key=$(echo "$tags" | jq '.TagSet[0].Key')
    tag_set_value=$(echo "$tags" | jq '.TagSet[0].Value')
    [[ $tag_set_key == '"'$key'"' ]] || fail "Key mismatch"
    [[ $tag_set_value == '"'$value'"' ]] || fail "Value mismatch"
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    [[ $tag_set_key == "$key" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$value" ]] || fail "Value mismatch"
  fi
  delete_bucket_tags "$1" "$BUCKET_ONE_NAME"

  get_bucket_tagging "$1" "$BUCKET_ONE_NAME" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "Error getting bucket tags third time"

  check_bucket_tags_empty "$1" "$BUCKET_ONE_NAME" || local check_result=$?
  [[ $check_result -eq 0 ]] || fail "error checking if bucket tags are empty"
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
  put_object "$1" "$test_file_folder"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket '$BUCKET_ONE_NAME'"

  get_object_tags "$1" "$BUCKET_ONE_NAME" $bucket_file || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "Error getting object tags"
  if [[ $1 == 'aws' ]]; then
    tag_set=$(echo "$tags" | jq '.TagSet')
    [[ $tag_set == "[]" ]] || [[ $tag_set == "" ]] || fail "Error:  tags not empty"
  elif [[ $tags != *"No tags found"* ]] && [[ $tags != "" ]]; then
    fail "no tags found (tags: $tags)"
  fi

  put_object_tag "$1" "$BUCKET_ONE_NAME" $bucket_file $key $value
  get_object_tags "$1" "$BUCKET_ONE_NAME" "$bucket_file" || local get_result_two=$?
  [[ $get_result_two -eq 0 ]] || fail "Error getting object tags"
  if [[ $1 == 'aws' ]]; then
    tag_set_key=$(echo "$tags" | jq -r '.TagSet[0].Key')
    tag_set_value=$(echo "$tags" | jq -r '.TagSet[0].Value')
    [[ $tag_set_key == "$key" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$value" ]] || fail "Value mismatch"
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    [[ $tag_set_key == "$key" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$value" ]] || fail "Value mismatch"
  fi

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

  put_object "$1" "$test_file_folder"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || put_result=$?
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

test_common_list_objects_file_count() {
  if [[ $# -ne 1 ]]; then
    echo "list objects greater than 1000 missing command type"
    return 1
  fi
  create_test_file_count 1001 || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "error creating test files"
  setup_bucket "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Failed to create bucket '$BUCKET_ONE_NAME'"
  put_object_multiple "$1" "$test_file_folder/file_*" "$BUCKET_ONE_NAME" || local put_result=$?
  [[ $put_result -eq 0 ]] || fail "Failed to copy files to bucket"
  list_objects "$1" "$BUCKET_ONE_NAME"
  if [[ $LOG_LEVEL -ge 5 ]]; then
    log 5 "Array: ${object_array[*]}"
  fi
  local file_count="${#object_array[@]}"
  [[ $file_count == 1001 ]] || fail "file count should be 1001, is $file_count"
  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
}

test_common_delete_object_tagging() {
  [[ $# -eq 1 ]] || fail "test common delete object tagging requires command type"

  bucket_file="bucket_file"
  tag_key="key"
  tag_value="value"

  create_test_files "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test files"

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  put_object "$1" "$test_file_folder"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || local copy_result=$?
  [[ $copy_result -eq 0 ]] || fail "Failed to add object to bucket"

  put_object_tag "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$tag_key" "$tag_value" || put_result=$?
  [[ $put_result -eq 0 ]] || fail "failed to add tags to object"

  get_and_verify_object_tags "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$tag_key" "$tag_value" || get_result=$?
  [[ $get_result -eq 0 ]] || fail "failed to get tags"

  delete_object_tagging "$1" "$BUCKET_ONE_NAME" "$bucket_file" || delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "error deleting object tagging"

  check_object_tags_empty "$1" "$BUCKET_ONE_NAME" "$bucket_file" || get_result=$?
  [[ $get_result -eq 0 ]] || fail "failed to get tags"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$bucket_file"
}

test_common_get_bucket_location() {
  [[ $# -eq 1 ]] || fail "test common get bucket location missing command type"
  setup_bucket "aws" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"
  get_bucket_location "aws" "$BUCKET_ONE_NAME"
  # shellcheck disable=SC2154
  [[ $bucket_location == "null" ]] || [[ $bucket_location == "us-east-1" ]] || fail "wrong location: '$bucket_location'"
}

test_common_put_bucket_acl() {
  [[ $# -eq 1 ]] || fail "test common put bucket acl missing command type"
  setup_bucket "$1" "$BUCKET_ONE_NAME" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating bucket"

  if ! user_exists "ABCDEFG"; then
    create_user "ABCDEFG" "HIJKLMN" user || create_result=$?
    [[ $create_result -eq 0 ]] || fail "Error creating user"
  fi

  get_bucket_acl "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"

  log 5 "Initial ACLs: $acl"
  id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq '.Owner.ID')
  if [[ $id != '"'"$AWS_ACCESS_KEY_ID"'"' ]]; then
    # in some cases, ID is canonical user ID rather than AWS_ACCESS_KEY_ID
    canonical_id=$(aws --no-verify-ssl s3api list-buckets --query 'Owner.ID') || local list_result=$?
    [[ $list_result -eq 0 ]] || fail "error getting canonical ID: $canonical_id"
    [[ $id == "$canonical_id" ]] || fail "acl ID doesn't match AWS key or canonical ID"
  fi

  acl_file="test-acl"

cat <<EOF > "$test_file_folder"/"$acl_file"
  {
    "Grants": [
      {
        "Grantee": {
          "ID": "ABCDEFG",
          "Type": "CanonicalUser"
        },
        "Permission": "READ"
      }
    ],
    "Owner": {
      "ID": "$AWS_ACCESS_KEY_ID"
    }
  }
EOF

  put_bucket_acl "$1" "$BUCKET_ONE_NAME" "$test_file_folder"/"$acl_file" || local put_result=$?
  [[ $put_result -eq 0 ]] || fail "Error putting acl"

  get_bucket_acl "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"

  log 5 "Acls after 1st put: $acl"
  public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants[0]')
  permission=$(echo "$public_grants" | jq -r '.Permission')
  [[ $permission == "READ" ]] || fail "incorrect permission ($permission)"

cat <<EOF > "$test_file_folder"/"$acl_file"
  {
    "Grants": [
      {
        "Grantee": {
          "ID": "ABCDEFG",
          "Type": "CanonicalUser"
        },
        "Permission": "FULL_CONTROL"
      }
    ],
    "Owner": {
      "ID": "$AWS_ACCESS_KEY_ID"
    }
  }
EOF

  put_bucket_acl "$1" "$BUCKET_ONE_NAME" "$test_file_folder"/"$acl_file" || local put_result=$?
  [[ $put_result -eq 0 ]] || fail "Error putting acl"

  get_bucket_acl "$1" "$BUCKET_ONE_NAME" || local result=$?
  [[ $result -eq 0 ]] || fail "Error retrieving acl"

  log 5 "Acls after 2nd put: $acl"
  public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants')
  public_grant_length=$(echo "$public_grants" | jq 'length')
  [[ $public_grant_length -eq 1 ]] || fail "incorrect grant length for private ACL ($public_grant_length)"
  permission=$(echo "$public_grants" | jq -r '.[0].Permission')
  [[ $permission == "FULL_CONTROL" ]] || fail "incorrect permission ($permission)"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
}

test_common_get_put_delete_bucket_policy() {
  [[ $# -eq 1 ]] || fail "get/put/delete policy test requires command type"

  policy_file="policy_file"

  create_test_files "$policy_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating policy file"

  effect="Allow"
  principal="*"
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"

  cat <<EOF > "$test_file_folder"/$policy_file
    {
      "Version": "2012-10-17",
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

  setup_bucket "$1" "$BUCKET_ONE_NAME" || local setup_result=$?
  [[ $setup_result -eq 0 ]] || fail "error setting up bucket"

  check_for_empty_policy "$1" "$BUCKET_ONE_NAME" || check_result=$?
  [[ $get_result -eq 0 ]] || fail "policy not empty"

  put_bucket_policy "$1" "$BUCKET_ONE_NAME" "$test_file_folder"/"$policy_file" || put_result=$?
  [[ $put_result -eq 0 ]] || fail "error putting bucket"

  get_bucket_policy "$1" "$BUCKET_ONE_NAME" || local get_result=$?
  [[ $get_result -eq 0 ]] || fail "error getting bucket policy after setting"

  returned_effect=$(echo "$bucket_policy" | jq -r '.Statement[0].Effect')
  [[ $effect == "$returned_effect" ]] || fail "effect mismatch ($effect, $returned_effect)"
  returned_principal=$(echo "$bucket_policy" | jq -r '.Statement[0].Principal')
  [[ $principal == "$returned_principal" ]] || fail "principal mismatch ($principal, $returned_principal)"
  returned_action=$(echo "$bucket_policy" | jq -r '.Statement[0].Action')
  [[ $action == "$returned_action" ]] || fail "action mismatch ($action, $returned_action)"
  returned_resource=$(echo "$bucket_policy" | jq -r '.Statement[0].Resource')
  [[ $resource == "$returned_resource" ]] || fail "resource mismatch ($resource, $returned_resource)"

  delete_bucket_policy "$1" "$BUCKET_ONE_NAME" || delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "error deleting policy"

  check_for_empty_policy "$1" "$BUCKET_ONE_NAME" || check_result=$?
  [[ $get_result -eq 0 ]] || fail "policy not empty after deletion"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
}
