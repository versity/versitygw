#!/usr/bin/env bash

# Copyright 2024 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

source ./tests/util_create_bucket.sh
source ./tests/util_mc.sh
source ./tests/util_multipart.sh
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
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/get_object_tagging.sh
source ./tests/commands/head_bucket.sh
source ./tests/commands/head_object.sh
source ./tests/commands/list_multipart_uploads.sh
source ./tests/commands/list_objects.sh
source ./tests/commands/list_parts.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_ownership_controls.sh
source ./tests/commands/put_object_legal_hold.sh
source ./tests/commands/put_object_lock_configuration.sh
source ./tests/commands/upload_part_copy.sh
source ./tests/commands/upload_part.sh
source ./tests/util_users.sh

# recursively delete an AWS bucket
# param:  client, bucket name
# fail if error
delete_bucket_recursive() {
  log 6 "delete_bucket_recursive"
  if [ $# -ne 2 ]; then
    log 2 "'delete_bucket_recursive' requires client, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 rb s3://"$2" --force 2>&1) || exit_code="$?"
  elif [[ $1 == "aws" ]] || [[ $1 == 's3api' ]]; then
    if ! delete_bucket_recursive_s3api "$2"; then
      log 2 "error deleting bucket recursively (s3api)"
      return 1
    fi
    return 0
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rb s3://"$2" --recursive 2>&1) || exit_code="$?"
  elif [[ $1 == "mc" ]]; then
    error=$(delete_bucket_recursive_mc "$2" 2>&1) || exit_code="$?"
  else
    log 2 "invalid client '$1'"
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

# params:  bucket name
# return 0 for success, 1 for error
add_governance_bypass_policy() {
  if [[ $# -ne 1 ]]; then
    log 2 "'add governance bypass policy' command requires bucket name"
    return 1
  fi
  if [[ -z "$GITHUB_ACTIONS" ]]; then
    if ! create_test_file_folder; then
      log 2 "error creating test file folder"
      return 1
    fi
  fi
  cat <<EOF > "$TEST_FILE_FOLDER/policy-bypass-governance.txt"
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
  if ! put_bucket_policy "s3api" "$1" "$TEST_FILE_FOLDER/policy-bypass-governance.txt"; then
    log 2 "error putting governance bypass policy"
    return 1
  fi
  return 0
}

log_bucket_policy() {
  if [ $# -ne 1 ]; then
    log 2 "'log_bucket_policy' requires bucket name"
    return
  fi
  if ! get_bucket_policy "s3api" "$1"; then
    log 2 "error getting bucket policy"
    return
  fi
  # shellcheck disable=SC2154
  log 5 "BUCKET POLICY: $bucket_policy"
}

# param: bucket name
# return 0 for success, 1 for failure
list_and_delete_objects() {
  if [ $# -ne 1 ]; then
    log 2 "'list_and_delete_objects' missing bucket name"
    return 1
  fi
  if ! list_objects 's3api' "$1"; then
    log 2 "error getting object list"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "objects: ${object_array[*]}"
  for object in "${object_array[@]}"; do
    if ! clear_object_in_bucket "$1" "$object"; then
      log 2 "error deleting object $object"
      return 1
    fi
  done
}

# param: bucket name
# return 0 for success, 1 for failure
check_ownership_rule_and_reset_acl() {
  if [ $# -ne 1 ]; then
    log 2 "'check_ownership_rule_and_reset_acl' requires bucket name"
    return 1
  fi
  if ! get_bucket_ownership_controls "$1"; then
    log 2 "error getting bucket ownership controls"
    return 1
  fi
  # shellcheck disable=SC2154
  if ! object_ownership_rule=$(echo "$bucket_ownership_controls" | jq -r ".OwnershipControls.Rules[0].ObjectOwnership" 2>&1); then
    log 2 "error getting object ownership rule: $object_ownership_rule"
    return 1
  fi
  if [[ $object_ownership_rule != "BucketOwnerEnforced" ]] && ! reset_bucket_acl "$1"; then
    log 2 "error resetting bucket ACL"
    return 1
  fi
}

# param: bucket name
# return 0 for success, 1 for error
check_and_disable_object_lock_config() {
  if [ $# -ne 1 ]; then
    log 2 "'check_and_disable_object_lock_config' requires bucket name"
    return 1
  fi

  local lock_config_exists=true
  if ! get_object_lock_configuration "$1"; then
    # shellcheck disable=SC2154
    if [[ "$get_object_lock_config_err" == *"does not exist"* ]]; then
      lock_config_exists=false
    else
      log 2 "error getting object lock config"
      return 1
    fi
  fi
  if [[ $lock_config_exists == true ]] && ! put_object_lock_configuration_disabled "$1"; then
    log 2 "error disabling object lock config"
    return 1
  fi
}

# restore bucket to pre-test state (or prep for deletion)
# param: bucket name
# return 0 on success, 1 on error
clear_bucket_s3api() {
  log 6 "clear_bucket_s3api"
  if [ $# -ne 1 ]; then
    log 2 "'clear_bucket_s3api' requires bucket name"
    return 1
  fi

  if [[ $LOG_LEVEL_INT -ge 5 ]]; then
    if ! log_bucket_policy "$1"; then
      log 2 "error logging bucket policy"
      return 1
    fi
  fi

  if ! list_and_delete_objects "$1"; then
    log 2 "error listing and deleting objects"
    return 1
  fi

  if ! delete_bucket_policy "s3api" "$1"; then
    log 2 "error deleting bucket policy"
    return 1
  fi

  #run check_ownership_rule_and_reset_acl "$1"
  #assert_success "error checking ownership rule and resetting acl"

  if ! check_and_disable_object_lock_config "$1"; then
    log 2 "error checking and disabling object lock config"
    return 1
  fi

  #if ! change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$AWS_ACCESS_KEY_ID"; then
  #  log 2 "error changing bucket owner back to root"
  #  return 1
  #fi
}

# params: bucket, object name
# return 0 for success, 1 for error
clear_object_in_bucket() {
  log 6 "clear_object_in_bucket"
  if [ $# -ne 2 ]; then
    log 2 "'clear_object_in_bucket' requires bucket, object name"
    return 1
  fi
  if ! delete_object 's3api' "$1" "$2"; then
    # shellcheck disable=SC2154
    log 2 "error deleting object $2: $delete_object_error"
    if ! check_for_and_remove_worm_protection "$1" "$2" "$delete_object_error"; then
      log 2 "error checking for and removing worm protection if needed"
      return 1
    fi
  fi
  return 0
}

# params: bucket, object, possible WORM error after deletion attempt
# return 0 for success, 1 for error
check_for_and_remove_worm_protection() {
  if [ $# -ne 3 ]; then
    log 2 "'check_for_and_remove_worm_protection' command requires bucket, object, error"
    return 1
  fi

  if [[ $3 == *"WORM"* ]]; then
    log 5 "WORM protection found"
    if ! put_object_legal_hold "$1" "$2" "OFF"; then
      log 2 "error removing object legal hold"
      return 1
    fi
    sleep 1
    if [[ $LOG_LEVEL_INT -ge 5 ]]; then
      log_worm_protection "$1" "$2"
    fi
    if ! add_governance_bypass_policy "$1"; then
      log 2 "error adding new governance bypass policy"
      return 1
    fi
    if ! delete_object_bypass_retention "$1" "$2" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"; then
      log 2 "error deleting object after legal hold removal"
      return 1
    fi
  fi
  return 0
}

# params: bucket name, object
log_worm_protection() {
  if ! get_object_legal_hold "$1" "$2"; then
    log 2 "error getting object legal hold status"
    return
  fi
  # shellcheck disable=SC2154
  log 5 "LEGAL HOLD: $legal_hold"
  if ! get_object_retention "$1" "$2"; then
    log 2 "error getting object retention"
    # shellcheck disable=SC2154
    if [[ $get_object_retention_error != *"NoSuchObjectLockConfiguration"* ]]; then
      return
    fi
  fi
  # shellcheck disable=SC2154
  log 5 "RETENTION: $retention"
}

# params:  bucket name
# return 0 if able to delete recursively, 1 if not
delete_bucket_recursive_s3api() {
  log 6 "delete_bucket_recursive_s3api"
  if [ $# -ne 1 ]; then
    log 2 "'delete_bucket_recursive_s3api' requires bucket name"
    return 1
  fi

  if ! clear_bucket_s3api "$1"; then
    log 2 "error clearing bucket (s3api)"
    return 1
  fi

  if ! delete_bucket 's3api' "$1"; then
    log 2 "error deleting bucket"
    return 1
  fi
  return 0
}

# params: client, bucket name
# return 0 on success, 1 on error
delete_bucket_contents() {
  log 6 "delete_bucket_contents"
  if [ $# -ne 2 ]; then
    log 2 "'delete_bucket_contents' requires client, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == "aws" ]] || [[ $1 == 's3api' ]]; then
    if ! clear_bucket_s3api "$2"; then
      log 2 "error clearing bucket (s3api)"
      return 1
    fi
  elif [[ $1 == "s3cmd" ]]; then
    delete_bucket_recursive "s3cmd" "$1"
  elif [[ $1 == "mc" ]]; then
    delete_bucket_recursive "mc" "$1"
  elif [[ $1 == "s3" ]]; then
    delete_bucket_recursive "s3" "$1"
  else
    log 2 "unrecognized client: '$1'"
    return 1
  fi
  return 0
}

# check if bucket exists
# param:  bucket name
# return 0 for true, 1 for false, 2 for error
bucket_exists() {
  if [ $# -ne 2 ]; then
    log 2 "bucket_exists command requires client, bucket name"
    return 2
  fi
  local exists=0
  head_bucket "$1" "$2" || exists=$?
  # shellcheck disable=SC2181
  if [ $exists -ne 0 ] && [ $exists -ne 1 ]; then
    log 2 "unexpected error checking if bucket exists"
    return 2
  fi
  if [ $exists -eq 0 ]; then
    return 0
  fi
  return 1
}

# param: bucket name
# return 1 for failure, 0 for success
get_object_ownership_rule_and_update_acl() {
  if [ $# -ne 1 ]; then
    log 2 "'get_object_ownership_rule_and_update_acl' requires bucket name"
    return 1
  fi
  if ! get_object_ownership_rule "$1"; then
    log 2 "error getting object ownership rule"
    return 1
  fi
  log 5 "object ownership rule: $object_ownership_rule"
  if [[ "$object_ownership_rule" != "BucketOwnerEnforced" ]] && ! put_bucket_canned_acl "$1" "private"; then
    log 2 "error resetting bucket ACLs"
    return 1
  fi
}

# params:  client, bucket name
# return 0 for success, 1 for error
delete_bucket_or_contents() {
  log 6 "delete_bucket_or_contents"
  if [ $# -ne 2 ]; then
    log 2 "'delete_bucket_or_contents' requires client, bucket name"
    return 1
  fi
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    if ! delete_bucket_contents "$1" "$2"; then
      log 2 "error deleting bucket contents"
      return 1
    fi

    if ! delete_bucket_policy "$1" "$2"; then
      log 2 "error deleting bucket policy"
      return 1
    fi

    if ! get_object_ownership_rule_and_update_acl "$2"; then
      log 2 "error getting object ownership rule and updating ACL"
      return 1
    fi

    if ! abort_all_multipart_uploads "$2"; then
      log 2 "error aborting all multipart uploads"
      return 1
    fi
    log 5 "bucket contents, policy, ACL deletion success"
    return 0
  fi
  if ! delete_bucket_recursive "$1" "$2"; then
    log 2 "error with recursive bucket delete"
    return 1
  fi
  log 5 "bucket deletion success"
  return 0
}

# params: client, bucket name
# return 0 for success, 1 for error
delete_bucket_or_contents_if_exists() {
  log 6 "delete_bucket_or_contents_if_exists"
  if [ $# -ne 2 ]; then
    log 2 "'delete_bucket_or_contents_if_exists' requires client, bucket name"
    return 1
  fi

  if bucket_exists "$1" "$2"; then
    if ! delete_bucket_or_contents "$1" "$2"; then
      log 2 "error deleting bucket and/or contents"
      return 1
    fi
    log 5 "bucket and/or bucket data deletion success"
    return 0
  fi
  return 0
}

# params:  client, bucket name(s)
# return 0 for success, 1 for failure
setup_buckets() {
  if [ $# -lt 2 ]; then
    log 2 "'setup_buckets' command requires client, bucket names"
    return 1
  fi
  for name in "${@:2}"; do
    if ! setup_bucket "$1" "$name"; then
      log 2 "error setting up bucket $name"
      return 1
    fi
  done
  return 0
}

# params:  client, bucket name
# return 0 on successful setup, 1 on error
setup_bucket() {
  log 6 "setup_bucket"
  if [ $# -ne 2 ]; then
    log 2 "'setup_bucket' requires client, bucket name"
    return 1
  fi

  if ! bucket_exists "$1" "$2" && [[ $RECREATE_BUCKETS == "false" ]]; then
    log 2 "When RECREATE_BUCKETS isn't set to \"true\", buckets should be pre-created by user"
    return 1
  fi

  if ! delete_bucket_or_contents_if_exists "$1" "$2"; then
    log 2 "error deleting bucket or contents if they exist"
    return 1
  fi

  log 5 "util.setup_bucket: command type: $1, bucket name: $2"
  if [[ $RECREATE_BUCKETS == "true" ]]; then
    if ! create_bucket "$1" "$2"; then
      log 2 "error creating bucket"
      return 1
    fi
  else
    log 5 "skipping bucket re-creation"
  fi

  if [[ $1 == "s3cmd" ]]; then
    log 5 "putting bucket ownership controls"
    if bucket_exists "s3cmd" "$2" && ! put_bucket_ownership_controls "$2" "BucketOwnerPreferred"; then
      log 2 "error putting bucket ownership controls"
      return 1
    fi
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

list_and_check_directory_obj() {
  #assert [ $# -eq 2 ]
  if [ $# -ne 2 ]; then
    log 2 "'list_and_check_directory_obj' requires client, file name"
    return 1
  fi
  if ! list_objects_with_prefix "$1" "$BUCKET_ONE_NAME" "$2/"; then
    log 2 "error listing objects with prefix"
    return 1
  fi
  if [ "$1" == "s3api" ]; then
    # shellcheck disable=SC2154
    if ! key=$(echo "$objects" | grep -v "InsecureRequestWarning" | jq -r ".Contents[0].Key" 2>&1); then
      log 2 "error getting key: $key"
      return 1
    fi
    if [ "$key" != "$2/" ]; then
      log 2 "key mismatch ($key, $2)"
      return 1
    fi
  elif [ "$1" == "s3" ]; then
    log 5 "$objects"
    filename=$(echo "$objects" | grep -v "InsecureRequestWarning" | awk '{print $4}')
    if [ "$filename" != "$2" ]; then
      log 2 "filename mismatch ($filename, $2)"
      return 1
    fi
  fi
  return 0
}