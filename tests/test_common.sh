#!/usr/bin/env bats

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