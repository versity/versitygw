#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/util.sh
source ./tests/util_file.sh
source ./tests/util_policy.sh
source ./tests/commands/copy_object.sh
source ./tests/commands/delete_bucket_tagging.sh
source ./tests/commands/delete_object_tagging.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_location.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/get_object.sh
source ./tests/commands/get_object_tagging.sh
source ./tests/commands/list_buckets.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_tagging.sh
source ./tests/commands/put_object_tagging.sh
source ./tests/commands/put_object.sh
source ./tests/commands/put_public_access_block.sh

test_common_multipart_upload() {
  if [[ $# -ne 1 ]]; then
    echo "multipart upload command missing command type"
    return 1
  fi
  bucket_file="largefile"

  create_large_file "$bucket_file" || local created=$?
  [[ $created -eq 0 ]] || fail "Error creating test file for multipart upload"

  setup_bucket "$1" "$BUCKET_ONE_NAME"
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

  assert [ $# -eq 1 ]

  setup_bucket "$1" "$BUCKET_ONE_NAME"

  bucket_exists "$1" "$BUCKET_ONE_NAME" || fail "failed bucket existence check"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME" || fail "failed to delete bucket"
}

test_common_copy_object() {
  if [[ $# -ne 1 ]]; then
    fail "copy object test requires command type"
  fi
  local object_name="test-object"
  create_test_files "$object_name" || fail "error creating test file"
  echo "test data" > "$test_file_folder/$object_name"

  setup_bucket "$1" "$BUCKET_ONE_NAME"
  setup_bucket "$1" "$BUCKET_TWO_NAME"

  if [[ $1 == 's3' ]]; then
    copy_object "$1" "$test_file_folder/$object_name" "$BUCKET_ONE_NAME" "$object_name" || fail "failed to copy object to bucket one"
  else
    put_object "$1" "$test_file_folder/$object_name" "$BUCKET_ONE_NAME" "$object_name" || fail "failed to put object to bucket one"
  fi
  if [[ $1 == 's3' ]]; then
    copy_object "$1" "s3://$BUCKET_ONE_NAME/$object_name" "$BUCKET_TWO_NAME" "$object_name" || fail "object not copied to bucket two"
  else
    copy_object "$1" "$BUCKET_ONE_NAME/$object_name" "$BUCKET_TWO_NAME" "$object_name" || fail "object not copied to bucket two"
  fi
  get_object "$1" "$BUCKET_TWO_NAME" "$object_name" "$test_file_folder/$object_name-copy" || fail "failed to retrieve object"

  compare_files "$test_file_folder/$object_name" "$test_file_folder/$object_name-copy" || fail "files not the same"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_bucket_or_contents "$1" "$BUCKET_TWO_NAME"
  delete_test_files "$object_name" "$object_name-copy"
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

  setup_bucket "$1" "$BUCKET_ONE_NAME"

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

  create_test_files "$object_name" || fail "error creating test file"
  echo "test data" > "$test_file_folder"/"$object_name"

  setup_bucket "$1" "$BUCKET_ONE_NAME"

  if [[ $1 == 's3' ]]; then
    copy_object "$1" "$test_file_folder/$object_name" "$BUCKET_ONE_NAME" "$object_name" || fail "failed to add object to bucket"
  else
    put_object "$1" "$test_file_folder/$object_name" "$BUCKET_ONE_NAME" "$object_name" || fail "failed to add object to bucket"
  fi
  object_exists "$1" "$BUCKET_ONE_NAME" "$object_name" || fail "object not added to bucket"

  get_object "$1" "$BUCKET_ONE_NAME" "$object_name" "$test_file_folder/${object_name}_copy" || fail "failed to get object"
  compare_files "$test_file_folder"/"$object_name" "$test_file_folder/${object_name}_copy" || fail "objects are different"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
  delete_test_files "$object_name" "${object_name}_copy"
}

test_common_get_set_versioning() {
  local object_name="test-object"
  create_test_files "$object_name" || local create_result=$?
  [[ $create_result -eq 0 ]] || fail "Error creating test file"

  setup_bucket "$1" "$BUCKET_ONE_NAME"

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

  setup_bucket "$1" "$BUCKET_ONE_NAME"
  setup_bucket "$1" "$BUCKET_TWO_NAME"

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
  setup_bucket "$1" "$BUCKET_ONE_NAME"
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

  setup_bucket "$1" "$BUCKET_ONE_NAME"

  get_bucket_tagging "$1" "$BUCKET_ONE_NAME" || fail "Error getting bucket tags first time"

  check_bucket_tags_empty "$1" "$BUCKET_ONE_NAME" || fail "error checking if bucket tags are empty"

  put_bucket_tagging "$1" "$BUCKET_ONE_NAME" $key $value || fail "error putting bucket tags"
  get_bucket_tagging "$1" "$BUCKET_ONE_NAME" || fail "Error getting bucket tags second time"

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
  delete_bucket_tagging "$1" "$BUCKET_ONE_NAME"

  get_bucket_tagging "$1" "$BUCKET_ONE_NAME" || fail "Error getting bucket tags third time"

  check_bucket_tags_empty "$1" "$BUCKET_ONE_NAME" || fail "error checking if bucket tags are empty"
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

  create_test_files "$bucket_file" || fail "error creating test files"
  setup_bucket "$1" "$BUCKET_ONE_NAME"
  put_object "$1" "$test_file_folder"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || fail "Failed to add object to bucket '$BUCKET_ONE_NAME'"

  get_object_tagging "$1" "$BUCKET_ONE_NAME" $bucket_file || fail "Error getting object tags"
  if [[ $1 == 'aws' ]]; then
    tag_set=$(echo "$tags" | jq '.TagSet')
    [[ $tag_set == "[]" ]] || [[ $tag_set == "" ]] || fail "Error:  tags not empty"
  elif [[ $tags != *"No tags found"* ]] && [[ $tags != "" ]]; then
    fail "no tags found (tags: $tags)"
  fi

  put_object_tagging "$1" "$BUCKET_ONE_NAME" $bucket_file $key $value || fail "error putting object tagging"
  get_object_tagging "$1" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error getting object tags"
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

  create_test_files "$bucket_file" || local created=$?
  dd if=/dev/urandom of="$test_file_folder/$bucket_file" bs=5M count=1 || fail "error creating test file"
  setup_bucket "$1" "$BUCKET_ONE_NAME"
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
  setup_bucket "$1" "$BUCKET_ONE_NAME"
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

  create_test_files "$bucket_file" || fail "Error creating test files"

  setup_bucket "$1" "$BUCKET_ONE_NAME"

  put_object "$1" "$test_file_folder"/"$bucket_file" "$BUCKET_ONE_NAME" "$bucket_file" || fail "Failed to add object to bucket"

  put_object_tagging "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$tag_key" "$tag_value" || fail "failed to add tags to object"

  get_and_verify_object_tags "$1" "$BUCKET_ONE_NAME" "$bucket_file" "$tag_key" "$tag_value" || fail "failed to get tags"

  delete_object_tagging "$1" "$BUCKET_ONE_NAME" "$bucket_file" || fail "error deleting object tagging"

  check_object_tags_empty "$1" "$BUCKET_ONE_NAME" "$bucket_file" || fail "failed to get tags"

  delete_bucket_or_contents "aws" "$BUCKET_ONE_NAME"
  delete_test_files "$bucket_file"
}

test_common_get_bucket_location() {
  [[ $# -eq 1 ]] || fail "test common get bucket location missing command type"
  setup_bucket "$1" "$BUCKET_ONE_NAME"
  get_bucket_location "$1" "$BUCKET_ONE_NAME"
  # shellcheck disable=SC2154
  [[ $bucket_location == "null" ]] || [[ $bucket_location == "us-east-1" ]] || fail "wrong location: '$bucket_location'"
}

test_put_bucket_acl_s3cmd() {
  if [[ $DIRECT != "true" ]]; then
    # https://github.com/versity/versitygw/issues/695
    skip
  fi
  setup_bucket  "s3cmd" "$BUCKET_ONE_NAME"
  put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred" || fail "error putting bucket ownership controls"

  username=$USERNAME_ONE
  if [[ $DIRECT != "true" ]]; then
    setup_user "$username" "HIJKLMN" "user" || fail "error creating user"
  fi
  sleep 5

  get_bucket_acl "s3cmd" "$BUCKET_ONE_NAME" || fail "error retrieving acl"
  log 5 "Initial ACLs: $acl"
  acl_line=$(echo "$acl" | grep "ACL")
  user_id=$(echo "$acl_line" | awk '{print $2}')
  if [[ $DIRECT == "true" ]]; then
    [[ $user_id == "$DIRECT_DISPLAY_NAME:" ]] || fail "ID mismatch ($user_id, $DIRECT_DISPLAY_NAME)"
  else
    [[ $user_id == "$AWS_ACCESS_KEY_ID:" ]] || fail "ID mismatch ($user_id, $AWS_ACCESS_KEY_ID)"
  fi
  permission=$(echo "$acl_line" | awk '{print $3}')
  [[ $permission == "FULL_CONTROL" ]] || fail "Permission mismatch ($permission)"

  if [[ $DIRECT == "true" ]]; then
    put_public_access_block_enable_public_acls "$BUCKET_ONE_NAME" || fail "error enabling public ACLs"
  fi
  put_bucket_canned_acl_s3cmd "$BUCKET_ONE_NAME" "--acl-public" || fail "error putting canned s3cmd ACL"

  get_bucket_acl "s3cmd" "$BUCKET_ONE_NAME" || fail "error retrieving acl"
  log 5 "ACL after read put: $acl"
  acl_lines=$(echo "$acl" | grep "ACL")
  log 5 "ACL lines:  $acl_lines"
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "$acl_lines"
  log 5 "lines: ${lines[*]}"
  [[ ${#lines[@]} -eq 2 ]] || fail "unexpected number of ACL lines: ${#lines[@]}"
  anon_name=$(echo "${lines[1]}" | awk '{print $2}')
  anon_permission=$(echo "${lines[1]}" | awk '{print $3}')
  [[ $anon_name == "*anon*:" ]] || fail "unexpected anon name: $anon_name"
  [[ $anon_permission == "READ" ]] || fail "unexpected anon permission: $anon_permission"

  delete_bucket_or_contents "s3cmd" "$BUCKET_ONE_NAME"
}

test_common_put_bucket_acl() {
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    # https://github.com/versity/versitygw/issues/716
    skip
  fi
  [[ $# -eq 1 ]] || fail "test common put bucket acl missing command type"
  setup_bucket  "$1" "$BUCKET_ONE_NAME"
  put_bucket_ownership_controls "$BUCKET_ONE_NAME" "BucketOwnerPreferred" || fail "error putting bucket ownership controls"

  username=$USERNAME_ONE
  setup_user "$username" "HIJKLMN" "user" || fail "error creating user"

  get_bucket_acl "$1" "$BUCKET_ONE_NAME" || fail "error retrieving acl"

  log 5 "Initial ACLs: $acl"
  id=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Owner.ID' 2>&1) || fail "error getting ID: $id"
  if [[ $id != "$AWS_ACCESS_KEY_ID" ]]; then
    # for direct, ID is canonical user ID rather than AWS_ACCESS_KEY_ID
    canonical_id=$(aws --no-verify-ssl s3api list-buckets --query 'Owner.ID' 2>&1) || fail "error getting canonical ID: $canonical_id"
    [[ $id == "$canonical_id" ]] || fail "acl ID doesn't match AWS key or canonical ID"
  fi

  acl_file="test-acl"
  create_test_files "$acl_file"

  if [[ $DIRECT == "true" ]]; then
    grantee="{\"Type\": \"Group\", \"URI\": \"http://acs.amazonaws.com/groups/global/AllUsers\"}"
  else
    grantee="{\"ID\": \"$username\", \"Type\": \"CanonicalUser\"}"
  fi

cat <<EOF > "$test_file_folder"/"$acl_file"
  {
    "Grants": [
      {
        "Grantee": $grantee,
        "Permission": "READ"
      }
    ],
    "Owner": {
      "ID": "$AWS_ACCESS_KEY_ID"
    }
  }
EOF

  log 6 "before 1st put acl"
  put_bucket_acl_s3api "$BUCKET_ONE_NAME" "$test_file_folder"/"$acl_file" || fail "error putting first acl"
  get_bucket_acl "$1" "$BUCKET_ONE_NAME" || fail "error retrieving second ACL"

  log 5 "Acls after 1st put: $acl"
  public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants[1]' 2>&1) || fail "error getting public grants: $public_grants"
  permission=$(echo "$public_grants" | jq -r '.Permission' 2>&1) || fail "error getting permission: $permission"
  [[ $permission == "READ" ]] || fail "incorrect permission ($permission)"

cat <<EOF > "$test_file_folder"/"$acl_file"
  {
    "Grants": [
      {
        "Grantee": {
          "ID": "$username",
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

  put_bucket_acl_s3api "$BUCKET_ONE_NAME" "$test_file_folder"/"$acl_file" || fail "error putting second acl"
  get_bucket_acl "$1" "$BUCKET_ONE_NAME" || fail "error retrieving second ACL"

  log 5 "Acls after 2nd put: $acl"
  public_grants=$(echo "$acl" | grep -v "InsecureRequestWarning" | jq -r '.Grants' 2>&1) || fail "error retrieving public grants: $public_grants"
  public_grant_length=$(echo "$public_grants" | jq -r 'length' 2>&1) || fail "Error retrieving public grant length: $public_grant_length"
  [[ $public_grant_length -eq 2 ]] || fail "incorrect grant length for private ACL ($public_grant_length)"
  permission=$(echo "$public_grants" | jq -r '.[0].Permission' 2>&1) || fail "Error retrieving permission: $permission"
  [[ $permission == "FULL_CONTROL" ]] || fail "incorrect permission ($permission)"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
}

test_common_get_put_delete_bucket_policy() {
  [[ $# -eq 1 ]] || fail "get/put/delete policy test requires command type"

  policy_file="policy_file"

  create_test_files "$policy_file" || fail "error creating policy file"

  effect="Allow"
  #principal="*"
  if [[ $DIRECT == "true" ]]; then
    principal="{\"AWS\": \"arn:aws:iam::$DIRECT_AWS_USER_ID:user/s3user\"}"
  else
    principal="\"*\""
  fi
  action="s3:GetObject"
  resource="arn:aws:s3:::$BUCKET_ONE_NAME/*"

  cat <<EOF > "$test_file_folder"/$policy_file
{
  "Version": "2012-10-17",
  "Statement": [
    {
       "Effect": "$effect",
       "Principal": $principal,
       "Action": "$action",
       "Resource": "$resource"
    }
  ]
}
EOF
  log 5 "POLICY: $(cat "$test_file_folder/$policy_file")"

  setup_bucket "$1" "$BUCKET_ONE_NAME"

  check_for_empty_policy "$1" "$BUCKET_ONE_NAME" || fail "policy not empty"

  put_bucket_policy "$1" "$BUCKET_ONE_NAME" "$test_file_folder"/"$policy_file" || fail "error putting bucket policy"

  get_bucket_policy "$1" "$BUCKET_ONE_NAME" || fail "error getting bucket policy after setting"

  # shellcheck disable=SC2154
  log 5 "POLICY:  $bucket_policy"
  statement=$(echo "$bucket_policy" | jq -r '.Statement[0]' 2>&1) || fail "error getting statement value: $statement"
  returned_effect=$(echo "$statement" | jq -r '.Effect' 2>&1) || fail "error getting effect: $returned_effect"
  [[ $effect == "$returned_effect" ]] || fail "effect mismatch ($effect, $returned_effect)"
  returned_principal=$(echo "$statement" | jq -r '.Principal')
  if [[ -n $DIRECT ]] && arn=$(echo "$returned_principal" | jq -r '.AWS' 2>&1); then
    [[ $arn == "arn:aws:iam::$DIRECT_AWS_USER_ID:user/s3user" ]] || fail "arn mismatch"
  else
    [[ $principal == "\"$returned_principal\"" ]] || fail "principal mismatch ($principal, $returned_principal)"
  fi
  returned_action=$(echo "$statement" | jq -r '.Action')
  [[ $action == "$returned_action" ]] || fail "action mismatch ($action, $returned_action)"
  returned_resource=$(echo "$statement" | jq -r '.Resource')
  [[ $resource == "$returned_resource" ]] || fail "resource mismatch ($resource, $returned_resource)"

  delete_bucket_policy "$1" "$BUCKET_ONE_NAME" || delete_result=$?
  [[ $delete_result -eq 0 ]] || fail "error deleting policy"

  check_for_empty_policy "$1" "$BUCKET_ONE_NAME" || check_result=$?
  [[ $get_result -eq 0 ]] || fail "policy not empty after deletion"

  delete_bucket_or_contents "$1" "$BUCKET_ONE_NAME"
}
