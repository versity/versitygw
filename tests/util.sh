#!/usr/bin/env bash

source ./tests/util_bucket_create.sh
source ./tests/util_mc.sh
source ./tests/logger.sh
source ./tests/commands/abort_multipart_upload.sh
source ./tests/commands/complete_multipart_upload.sh
source ./tests/commands/create_multipart_upload.sh
source ./tests/commands/create_bucket.sh
source ./tests/commands/delete_bucket.sh
source ./tests/commands/delete_bucket_policy.sh
source ./tests/commands/delete_object.sh
source ./tests/commands/get_bucket_acl.sh
source ./tests/commands/get_bucket_ownership_controls.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/get_object_tagging.sh
source ./tests/commands/head_bucket.sh
source ./tests/commands/head_object.sh
source ./tests/commands/list_objects.sh
source ./tests/commands/list_parts.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_ownership_controls.sh
source ./tests/commands/put_object_lock_configuration.sh
source ./tests/commands/upload_part_copy.sh
source ./tests/commands/upload_part.sh

# recursively delete an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket_recursive() {
  if [ $# -ne 2 ]; then
    log 2 "delete bucket missing command type, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 rb s3://"$2" --force 2>&1) || exit_code="$?"
  elif [[ $1 == "aws" ]] || [[ $1 == 's3api' ]]; then
    delete_bucket_recursive_s3api "$2" || exit_code="$?"
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rb s3://"$2" --recursive 2>&1) || exit_code="$?"
  elif [[ $1 == "mc" ]]; then
    error=$(delete_bucket_recursive_mc "$2") || exit_code="$?"
  else
    log 2 "invalid command type '$1'"
    return 1
  fi

  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    else
      log 2 "error deleting bucket recursively: $error"
      return 1
    fi
  fi
  return 0
}

add_governance_bypass_policy() {
  if [[ $# -ne 1 ]]; then
    log 2 "'add governance bypass policy' command requires command ID"
    return 1
  fi
  test_file_folder=$PWD
  if [[ -z "$GITHUB_ACTIONS" ]]; then
    create_test_file_folder
  fi
  cat <<EOF > "$test_file_folder/policy-bypass-governance.txt"
{
  "Version": "dummy",
  "Statement": [
    {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "s3:BypassGovernanceRetention",
       "Resource": "arn:aws:s3:::$1/*"
    }
  ]
}
EOF
  put_bucket_policy "s3api" "$1" "$test_file_folder/policy-bypass-governance.txt" || fail "error putting bucket policy"
}

clear_bucket_s3api() {
  if ! list_objects 's3api' "$1"; then
    log 2 "error listing objects"
    return 1
  fi
  # shellcheck disable=SC2154
  for object in "${object_array[@]}"; do
    if ! delete_object 's3api' "$1" "$object"; then
      log 2 "error deleting object $object"
      if [[ $delete_object_error == *"WORM"* ]]; then
        log 5 "WORM protection found"
        if ! put_object_legal_hold "$1" "$object" "OFF"; then
          log 2 "error removing object legal hold"
          return 1
        fi
        sleep 1
        if [[ $LOG_LEVEL_INT -ge 5 ]]; then
          if ! get_object_legal_hold "$1" "$object"; then
            log 2 "error getting object legal hold status"
            return 1
          fi
          log 5 "LEGAL HOLD: $legal_hold"
          if ! get_object_retention "$1" "$object"; then
            log 2 "error getting object retention"
            if [[ $get_object_retention_error != *"NoSuchObjectLockConfiguration"* ]]; then
              return 1
            fi
          fi
          log 5 "RETENTION: $retention"
          get_bucket_policy "s3api" "$1" || fail "error getting bucket policy"
          log 5 "BUCKET POLICY: $bucket_policy"
        fi
        add_governance_bypass_policy "$1" || fail "error adding governance bypass policy"
        if ! delete_object_bypass_retention "$1" "$object" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"; then
          log 2 "error deleting object after legal hold removal"
          return 1
        fi
        continue
      fi
      return 1
    fi
  done
  delete_bucket_policy "s3api" "$1" || fail "error deleting bucket policy"
  # TODO uncomment after #716 is fixed
  #reset_bucket_acl "$1" || fail "error resetting bucket ACLs"
  put_object_lock_configuration_disabled "$1" || fail "error removing object lock config"
  #change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$AWS_ACCESS_KEY_ID" || fail "error changing bucket owner"
}

delete_bucket_recursive_s3api() {
  if [[ $# -ne 1 ]]; then
    log 2 "delete bucket recursive command for s3api requires bucket name"
    return 1
  fi

  clear_bucket_s3api "$1" || fail "error clearing bucket"

  delete_bucket 's3api' "$1" || local delete_bucket_result=$?
  if [[ $delete_bucket_result -ne 0 ]]; then
    log 2 "error deleting bucket"
    return 1
  fi
  return 0
}

# delete contents of a bucket
# param:  command type, bucket name
# return 0 for success, 1 for failure
delete_bucket_contents() {
  if [ $# -ne 2 ]; then
    log 2 "delete bucket missing command id, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == "aws" ]] || [[ $1 == 's3api' ]]; then
    clear_bucket_s3api "$2" || exit_code="$?"
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate del s3://"$2" --recursive --force 2>&1) || exit_code="$?"
  elif [[ $1 == "mc" ]]; then
    error=$(mc --insecure rm --force --recursive "$MC_ALIAS"/"$2" 2>&1) || exit_code="$?"
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error deleting bucket contents: $error"
    return 1
  fi
  return 0
}

# check if bucket exists
# param:  bucket name
# return 0 for true, 1 for false, 2 for error
bucket_exists() {
  if [ $# -ne 2 ]; then
    log 2 "bucket exists check missing command type, bucket name"
    return 2
  fi

  if ! head_bucket "$1" "$2"; then
    # shellcheck disable=SC2154
    bucket_info=$(echo "$bucket_info" | grep -v "InsecureRequestWarning")
    log 5 "$bucket_info"
    if [[ "$bucket_info" == *"404"* ]] || [[ "$bucket_info" == *"does not exist"* ]]; then
      log 5 "bucket not found"
      return 1
    fi
    log 2 "error checking if bucket exists"
    return 2
  fi
  return 0
}

abort_all_multipart_uploads() {
  assert [ $# -eq 1 ]
  run aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1"
  # shellcheck disable=SC2154
  assert_success "error listing uploads: $output"
  log 5 "UPLOADS: $output"
  if ! upload_set=$(echo "$output" | grep -v "InsecureRequestWarning" | jq -c '.Uploads[]' 2>&1); then
    if [[ $upload_set == *"Cannot iterate over null"* ]]; then
      return 0
    fi
    fail "error getting upload set: $upload_set"
  fi
  log 5 "UPLOAD SET: $upload_set"
  for upload in $upload_set; do
    log 5 "UPLOAD: $upload"
    upload_id=$(echo "$upload" | jq -r ".UploadId" 2>&1)
    assert [ $? -eq 0 ]
    log 5 "upload ID: $upload_id"
    key=$(echo "$upload" | jq -r ".Key" 2>&1)
    assert [ $? -eq 0 ]
    log 5 "Key: $key"

    log 5 "Aborting multipart upload for key: $key, UploadId: $upload_id"
    run aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" --key "$key" --upload-id "$upload_id"
    assert_success "error aborting upload: $output"
  done
}

# delete buckets or just the contents depending on RECREATE_BUCKETS parameter
# params:  command type, bucket name
# return:  0 for success, 1 for failure
delete_bucket_or_contents() {
  if [ $# -ne 2 ]; then
    log 2 "delete bucket or contents function requires command type, bucket name"
    return 1
  fi
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    if ! delete_bucket_contents "$1" "$2"; then
      log 2 "error deleting bucket contents"
      return 1
    fi
    if ! delete_bucket_policy "$1" "$2"; then
      log 2 "error deleting bucket policies"
      return 1
    fi
    if ! get_object_ownership_rule "$2"; then
      log 2 "error getting object ownership rule"
      return 1
    fi
    log 5 "object ownership rule: $object_ownership_rule"
    if [[ "$object_ownership_rule" != "BucketOwnerEnforced" ]] && ! put_bucket_canned_acl "$2" "private"; then
      log 2 "error resetting bucket ACLs"
      return 1
    fi
    run abort_all_multipart_uploads "$2"
    assert_success "error aborting multipart uploads"
    log 5 "bucket contents, policy, ACL deletion success"
    return 0
  fi
  if ! delete_bucket_recursive "$1" "$2"; then
    log 2 "Bucket deletion error"
    return 1
  fi
  log 5 "bucket deletion success"
  return 0
}

delete_bucket_or_contents_if_exists() {
  if [ $# -ne 2 ]; then
    log 2 "bucket creation function requires command type, bucket name"
    return 1
  fi
  local bucket_exists_result
  bucket_exists "$1" "$2" || local bucket_exists_result=$?
  if [[ $bucket_exists_result -eq 2 ]]; then
    log 2 "Bucket existence check error"
    return 1
  fi
  if [[ $bucket_exists_result -eq 0 ]]; then
    if ! delete_bucket_or_contents "$1" "$2"; then
      log 2 "error deleting bucket or contents"
      return 1
    fi
    log 5 "bucket and/or bucket data deletion success"
    return 0
  fi
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    log 2 "When RECREATE_BUCKETS isn't set to \"true\", buckets should be pre-created by user"
    return 1
  fi
  return 0
}

# if RECREATE_BUCKETS is set to true create bucket, deleting it if it exists to clear state.  If not,
# check to see if it exists and return an error if it does not.
# param:  bucket name
# return 0 for success, 1 for failure
setup_bucket() {
  assert [ $# -eq 2 ]
  if [[ $1 == "s3cmd" ]]; then
    log 5 "putting bucket ownership controls"
    put_bucket_ownership_controls "$2" "BucketOwnerPreferred"
  fi
  if ! delete_bucket_or_contents_if_exists "$1" "$2"; then
    log 2 "error deleting bucket, or checking for bucket existence"
    return 1
  fi
  local create_result
  log 5 "util.setup_bucket: command type: $1, bucket name: $2"
  if [[ $RECREATE_BUCKETS == "true" ]]; then
    if ! create_bucket "$1" "$2"; then
      log 2 "Error creating bucket"
      return 1
    fi
    log 5 "bucket creation success"
    if [[ $1 == "s3cmd" ]]; then
      log 5 "putting bucket ownership controls"
      put_bucket_ownership_controls "$2" "BucketOwnerPreferred" || fail "putting bucket ownership controls failed"
    fi
  else
    log 5 "skipping bucket re-creation"
  fi
  return 0
}

# check if object exists on S3 via gateway
# param:  command, object path
# return 0 for true, 1 for false, 2 for error
object_exists() {
  if [ $# -ne 3 ]; then
    log 2 "object exists check missing command, bucket name, object name"
    return 2
  fi
  head_object "$1" "$2" "$3" || local head_object_result=$?
  if [[ $head_object_result -eq 2 ]]; then
    log 2 "error checking if object exists"
    return 2
  fi
  # shellcheck disable=SC2086
  return $head_object_result
}

put_object_with_metadata() {
  if [ $# -ne 6 ]; then
    echo "put object command requires command type, source, destination, key, metadata key, metadata value"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" --metadata "{\"$5\":\"$6\"}") || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  return 0
}

get_object_metadata() {
  if [ $# -ne 3 ]; then
    echo "get object metadata command requires command type, bucket, key"
    return 1
  fi

  local exit_code=0
  if [[ $1 == 'aws' ]]; then
    metadata_struct=$(aws --no-verify-ssl s3api head-object --bucket "$2" --key "$3") || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  log 5 "raw metadata: $metadata_struct"
  metadata=$(echo "$metadata_struct" | jq '.Metadata')
  log 5 "metadata: $metadata"
  export metadata
  return 0
}

put_object_multiple() {
  if [ $# -ne 3 ]; then
    echo "put object command requires command type, source, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 'aws' ]] || [[ $1 == 's3' ]]; then
    # shellcheck disable=SC2086
    error=$(aws --no-verify-ssl s3 cp "$(dirname "$2")" s3://"$3" --recursive --exclude="*" --include="$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    # shellcheck disable=SC2086
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put $2 "s3://$3/" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    # shellcheck disable=SC2086
    error=$(mc --insecure cp $2 "$MC_ALIAS"/"$3" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  else
    log 5 "$error"
  fi
  return 0
}

# add object to versitygw if it doesn't exist
# params:  source file, destination copy location
# return 0 for success or already exists, 1 for failure
check_and_put_object() {
  if [ $# -ne 3 ]; then
    echo "check and put object function requires source, bucket, destination"
    return 1
  fi
  object_exists "aws" "$2" "$3" || local exists_result=$?
  if [ "$exists_result" -eq 2 ]; then
    echo "error checking if object exists"
    return 1
  fi
  if [ "$exists_result" -eq 1 ]; then
    copy_object "$1" "$2" || local copy_result=$?
    if [ "$copy_result" -ne 0 ]; then
      echo "error adding object"
      return 1
    fi
  fi
  return 0
}

remove_insecure_request_warning() {
  if [[ $# -ne 1 ]]; then
    echo "remove insecure request warning requires input lines"
    return 1
  fi
  parsed_output=()
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      parsed_output+=("$line")
    fi
  done <<< "$1"
  export parsed_output
}

# check if bucket info can be retrieved
# param:  path of bucket or folder
# return 0 for yes, 1 for no, 2 for error
bucket_is_accessible() {
  if [ $# -ne 1 ]; then
    echo "bucket accessibility check missing bucket name"
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws --no-verify-ssl s3api head-bucket --bucket "$1" 2>&1) || exit_code="$?"
  if [ $exit_code -eq 0 ]; then
    return 0
  fi
  if [[ "$error" == *"500"* ]]; then
    return 1
  fi
  echo "Error checking bucket accessibility: $error"
  return 2
}

# check if object info (etag) is accessible
# param:  path of object
# return 0 for yes, 1 for no, 2 for error
object_is_accessible() {
  if [ $# -ne 2 ]; then
    echo "object accessibility check missing bucket and/or key"
    return 2
  fi
  local exit_code=0
  object_data=$(aws --no-verify-ssl s3api head-object --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "Error obtaining object data: $object_data"
    return 2
  fi
  etag=$(echo "$object_data" | grep -v "InsecureRequestWarning" | jq '.ETag')
  if [[ "$etag" == '""' ]]; then
    return 1
  fi
  return 0
}

# get object acl
# param:  object path
# export acl for success, return 1 for error
get_object_acl() {
  if [ $# -ne 2 ]; then
    echo "object ACL command missing object name"
    return 1
  fi
  local exit_code=0
  acl=$(aws --no-verify-ssl s3api get-object-acl --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "Error getting object ACLs: $acl"
    return 1
  fi
  export acl
}

check_tags_empty() {
  if [[ $# -ne 1 ]]; then
    echo "check tags empty requires command type"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    if [[ $tags != "" ]]; then
      tag_set=$(echo "$tags" | jq '.TagSet')
      if [[ $tag_set != "[]" ]]; then
        echo "error:  tags not empty: $tags"
        return 1
      fi
    fi
  else
    if [[ $tags != "" ]] && [[ $tags != *"No tags found"* ]]; then
      echo "Error:  tags not empty: $tags"
      return 1
    fi
  fi
  return 0
}

check_object_tags_empty() {
  if [[ $# -ne 3 ]]; then
    echo "bucket tags empty check requires command type, bucket, and key"
    return 2
  fi
  if ! get_object_tagging "$1" "$2" "$3"; then
    echo "failed to get tags"
    return 2
  fi
  check_tags_empty "$1" || local check_result=$?
  # shellcheck disable=SC2086
  return $check_result
}

check_bucket_tags_empty() {
  if [[ $# -ne 2 ]]; then
    echo "bucket tags empty check requires command type, bucket"
    return 2
  fi
  if ! get_bucket_tagging "$1" "$2"; then
    echo "failed to get tags"
    return 2
  fi
  check_tags_empty "$1" || local check_result=$?
  # shellcheck disable=SC2086
  return $check_result
}

get_and_verify_object_tags() {
  if [[ $# -ne 5 ]]; then
    echo "get and verify object tags missing command type, bucket, key, tag key, tag value"
    return 1
  fi
  get_object_tagging "$1" "$2" "$3" || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    echo "failed to get tags"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    tag_set_key=$(echo "$tags" | jq '.TagSet[0].Key')
    tag_set_value=$(echo "$tags" | jq '.TagSet[0].Value')
    if [[ $tag_set_key != '"'$4'"' ]]; then
      echo "Key mismatch ($tag_set_key, \"$4\")"
      return 1
    fi
    if [[ $tag_set_value != '"'$5'"' ]]; then
      echo "Value mismatch ($tag_set_value, \"$5\")"
      return 1
    fi
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    [[ $tag_set_key == "$4" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$5" ]] || fail "Value mismatch"
  fi
  return 0
}

# list objects in bucket, v1
# param:  bucket
# export objects on success, return 1 for failure
list_objects_s3api_v1() {
  if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "list objects command requires bucket, (optional) delimiter"
    return 1
  fi
  if [ "$2" == "" ]; then
    objects=$(aws --no-verify-ssl s3api list-objects --bucket "$1") || local result=$?
  else
    objects=$(aws --no-verify-ssl s3api list-objects --bucket "$1" --delimiter "$2") || local result=$?
  fi
  if [[ $result -ne 0 ]]; then
    echo "error listing objects: $objects"
    return 1
  fi
  export objects
}

# perform all parts of a multipart upload before completion command
# params:  bucket, key, file to split and upload, number of file parts to upload
# return:  0 for success, 1 for failure
multipart_upload_before_completion() {
  if [ $# -ne 4 ]; then
    log 2 "multipart upload pre-completion command missing bucket, key, file, and/or part count"
    return 1
  fi

  if ! split_file "$3" "$4"; then
    log 2 "error splitting file"
    return 1
  fi

  if ! create_multipart_upload "$1" "$2"; then
    log 2 "error creating multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    # shellcheck disable=SC2154
    if ! upload_part "$1" "$2" "$upload_id" "$3" "$i"; then
      echo "error uploading part $i"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  export parts
}

multipart_upload_before_completion_with_params() {
  if [ $# -ne 10 ]; then
    log 2 "multipart upload command missing bucket, key, file, part count, content type, metadata, hold status, lock mode, retain until date, tagging"
    return 1
  fi

  split_file "$3" "$4" || split_result=$?
  if [[ $split_result -ne 0 ]]; then
    log 2 "error splitting file"
    return 1
  fi

  create_multipart_upload_params "$1" "$2" "$5" "$6" "$7" "$8" "$9" "${10}" || local create_result=$?
  if [[ $create_result -ne 0 ]]; then
    log 2 "error creating multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    upload_part "$1" "$2" "$upload_id" "$3" "$i" || local upload_result=$?
    if [[ $upload_result -ne 0 ]]; then
      log 2 "error uploading part $i"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  export parts
}

multipart_upload_before_completion_custom() {
  if [ $# -lt 4 ]; then
    log 2 "multipart upload custom command missing bucket, key, file, part count, and/or optional params"
    return 1
  fi

  split_file "$3" "$4" || local split_result=$?
  if [[ $split_result -ne 0 ]]; then
    log 2 "error splitting file"
    return 1
  fi

  # shellcheck disable=SC2086 disable=SC2048
  create_multipart_upload_custom "$1" "$2" ${*:5} || local create_result=$?
  if [[ $create_result -ne 0 ]]; then
    log 2 "error creating multipart upload"
    return 1
  fi
  log 5 "upload ID: $upload_id"

  parts="["
  for ((i = 1; i <= $4; i++)); do
    upload_part "$1" "$2" "$upload_id" "$3" "$i" || local upload_result=$?
    if [[ $upload_result -ne 0 ]]; then
      log 2 "error uploading part $i"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  export parts
}

multipart_upload_custom() {
  if [ $# -lt 4 ]; then
    log 2 "multipart upload custom command missing bucket, key, file, part count, and/or optional additional params"
    return 1
  fi

  # shellcheck disable=SC2086 disable=SC2048
  multipart_upload_before_completion_custom "$1" "$2" "$3" "$4" ${*:5} || local result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  log 5 "upload ID: $upload_id, parts: $parts"
  complete_multipart_upload "$1" "$2" "$upload_id" "$parts" || local completed=$?
  if [[ $completed -ne 0 ]]; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

multipart_upload() {
  if [ $# -ne 4 ]; then
    log 2 "multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  multipart_upload_before_completion "$1" "$2" "$3" "$4" || local result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  complete_multipart_upload "$1" "$2" "$upload_id" "$parts" || local completed=$?
  if [[ $completed -ne 0 ]]; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

# perform a multi-part upload
# params:  bucket, key, source file location, number of parts
# return 0 for success, 1 for failure
multipart_upload_with_params() {
  if [ $# -ne 10 ]; then
    log 2 "multipart upload command requires bucket, key, file, part count, content type, metadata, hold status, lock mode, retain until date, tagging"
    return 1
  fi
  log 5 "1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: ${10}"

  multipart_upload_before_completion_with_params "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" || result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi
  log 5 "Upload parts:  $parts"

  complete_multipart_upload "$1" "$2" "$upload_id" "$parts" || local completed=$?
  if [[ $completed -ne 0 ]]; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

# run upload, then abort it
# params:  bucket, key, local file location, number of parts to split into before uploading
# return 0 for success, 1 for failure
run_then_abort_multipart_upload() {
  if [ $# -ne 4 ]; then
    log 2 "run then abort multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  if ! multipart_upload_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  if ! abort_multipart_upload "$1" "$2" "$upload_id"; then
    log 2 "error aborting multipart upload"
    return 1
  fi
  return 0
}

# copy a file to/from S3
# params:  source, destination
# return 0 for success, 1 for failure
copy_file() {
  if [ $# -ne 2 ]; then
    echo "copy file command requires src and dest"
    return 1
  fi

  local result
  error=$(aws --no-verify-ssl s3 cp "$1" "$2") || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error copying file: $error"
    return 1
  fi
  return 0
}

# list parts of an unfinished multipart upload
# params:  bucket, key, local file location, and parts to split into before upload
# export parts on success, return 1 for error
start_multipart_upload_and_list_parts() {
  if [ $# -ne 4 ]; then
    log 2 "list multipart upload parts command requires bucket, key, file, and part count"
    return 1
  fi

  if ! multipart_upload_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  if ! list_parts "$1" "$2" "$upload_id"; then
    log 2 "Error listing multipart upload parts: $listed_parts"
    return 1
  fi
  export listed_parts
}

# list unfinished multipart uploads
# params:  bucket, key one, key two
# export current two uploads on success, return 1 for error
create_and_list_multipart_uploads() {
  if [ $# -ne 3 ]; then
    log 2 "list multipart uploads command requires bucket and two keys"
    return 1
  fi

  if ! create_multipart_upload "$1" "$2"; then
    log 2 "error creating multpart upload"
    return 1
  fi

  if ! create_multipart_upload "$1" "$3"; then
    log 2 "error creating multpart upload two"
    return 1
  fi

  if ! list_multipart_uploads "$1"; then
    echo "error listing uploads"
    return 1
  fi
  return 0
}

multipart_upload_from_bucket() {
  if [ $# -ne 4 ]; then
    echo "multipart upload from bucket command missing bucket, copy source, key, and/or part count"
    return 1
  fi

  split_file "$3" "$4" || split_result=$?
  if [[ $split_result -ne 0 ]]; then
    echo "error splitting file"
    return 1
  fi

  for ((i=0;i<$4;i++)) {
    echo "key: $3"
    put_object "s3api" "$3-$i" "$1" "$2-$i" || copy_result=$?
    if [[ $copy_result -ne 0 ]]; then
      echo "error copying object"
      return 1
    fi
  }

  create_multipart_upload "$1" "$2-copy" || upload_result=$?
  if [[ $upload_result -ne 0 ]]; then
    echo "error running first multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    upload_part_copy "$1" "$2-copy" "$upload_id" "$2" "$i" || local upload_result=$?
    if [[ $upload_result -ne 0 ]]; then
      echo "error uploading part $i"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}') || local completed=$?
  if [[ $completed -ne 0 ]]; then
    echo "Error completing upload: $error"
    return 1
  fi
  return 0
}

multipart_upload_from_bucket_range() {
  if [ $# -ne 5 ]; then
    echo "multipart upload from bucket with range command requires bucket, copy source, key, part count, and range"
    return 1
  fi

  split_file "$3" "$4" || local split_result=$?
  if [[ $split_result -ne 0 ]]; then
    echo "error splitting file"
    return 1
  fi

  for ((i=0;i<$4;i++)) {
    echo "key: $3"
    log 5 "file info: $(ls -l "$3"-"$i")"
    put_object "s3api" "$3-$i" "$1" "$2-$i" || local copy_result=$?
    if [[ $copy_result -ne 0 ]]; then
      echo "error copying object"
      return 1
    fi
  }

  create_multipart_upload "$1" "$2-copy" || local create_multipart_result=$?
  if [[ $create_multipart_result -ne 0 ]]; then
    echo "error running first multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    upload_part_copy_with_range "$1" "$2-copy" "$upload_id" "$2" "$i" "$5" || local upload_part_copy_result=$?
    if [[ $upload_part_copy_result -ne 0 ]]; then
      # shellcheck disable=SC2154
      echo "error uploading part $i: $upload_part_copy_error"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}') || local completed=$?
  if [[ $completed -ne 0 ]]; then
    echo "Error completing upload: $error"
    return 1
  fi
  return 0
}

create_presigned_url() {
  if [[ $# -ne 3 ]]; then
    echo "create presigned url function requires command type, bucket, and filename"
    return 1
  fi

  local presign_result=0
  if [[ $1 == 'aws' ]]; then
    presigned_url=$(aws s3 presign "s3://$2/$3" --expires-in 900) || presign_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    presigned_url=$(s3cmd --no-check-certificate "${S3CMD_OPTS[@]}" signurl "s3://$2/$3" "$(echo "$(date +%s)" + 900 | bc)") || presign_result=$?
  elif [[ $1 == 'mc' ]]; then
    presigned_url_data=$(mc --insecure share download --recursive "$MC_ALIAS/$2/$3") || presign_result=$?
    presigned_url="${presigned_url_data#*Share: }"
  else
    echo "unrecognized command type $1"
    return 1
  fi
  if [[ $presign_result -ne 0 ]]; then
    echo "error generating presigned url: $presigned_url"
    return 1
  fi
  export presigned_url
}
