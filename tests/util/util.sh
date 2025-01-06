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

source ./tests/util/util_bucket.sh
source ./tests/util/util_create_bucket.sh
source ./tests/util/util_mc.sh
source ./tests/util/util_multipart.sh
source ./tests/util/util_versioning.sh
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
source ./tests/commands/get_object_legal_hold.sh
source ./tests/commands/get_object_lock_configuration.sh
source ./tests/commands/head_bucket.sh
source ./tests/commands/head_object.sh
source ./tests/commands/list_multipart_uploads.sh
source ./tests/commands/list_objects.sh
source ./tests/commands/list_parts.sh
source ./tests/commands/put_bucket_acl.sh
source ./tests/commands/put_bucket_ownership_controls.sh
source ./tests/commands/put_bucket_policy.sh
source ./tests/commands/put_bucket_versioning.sh
source ./tests/commands/put_object_legal_hold.sh
source ./tests/commands/put_object_lock_configuration.sh
source ./tests/commands/upload_part_copy.sh
source ./tests/commands/upload_part.sh
source ./tests/util/util_users.sh

# params:  bucket name
# return 0 for success, 1 for error
add_governance_bypass_policy() {
  if [[ $# -ne 1 ]]; then
    log 2 "'add governance bypass policy' command requires bucket name"
    return 1
  fi
  cat <<EOF > "$TEST_FILE_FOLDER/policy-bypass-governance.txt"
{
  "Version": "2012-10-17",
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

  if ! delete_old_versions "$1"; then
    log 2 "error deleting old version"
    return 1
  fi
  return 0
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

check_object_lock_config() {
  if [ $# -ne 1 ]; then
    log 2 "'check_object_lock_config' requires bucket name"
    return 1
  fi
  lock_config_exists=true
  if ! get_object_lock_configuration "$1"; then
    # shellcheck disable=SC2154
    if [[ "$get_object_lock_config_err" == *"does not exist"* ]]; then
      # shellcheck disable=SC2034
      lock_config_exists=false
    else
      log 2 "error getting object lock config"
      return 1
    fi
  fi
  return 0
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
# return 0 for success, 1 for no WORM protection, 2 for error
check_for_and_remove_worm_protection() {
  if [ $# -ne 3 ]; then
    log 2 "'check_for_and_remove_worm_protection' command requires bucket, object, error"
    return 2
  fi

  if [[ $3 == *"WORM"* ]]; then
    log 5 "WORM protection found"
    if ! put_object_legal_hold "$1" "$2" "OFF"; then
      log 2 "error removing object legal hold"
      return 2
    fi
    sleep 1
    if [[ $LOG_LEVEL_INT -ge 5 ]]; then
      log_worm_protection "$1" "$2"
    fi
    if ! add_governance_bypass_policy "$1"; then
      log 2 "error adding new governance bypass policy"
      return 2
    fi
    if ! delete_object_bypass_retention "$1" "$2" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"; then
      log 2 "error deleting object after legal hold removal"
      return 2
    fi
  else
    log 5 "no WORM protection found"
    return 1
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
    log 2 "put object command requires command type, source, destination, key, metadata key, metadata value"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" --metadata "{\"$5\":\"$6\"}") || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    log 2 "error copying object to bucket: $error"
    return 1
  fi
  return 0
}

get_object_metadata() {
  if [ $# -ne 3 ]; then
    log 2 "get object metadata command requires command type, bucket, key"
    return 1
  fi

  local exit_code=0
  if [[ $1 == 's3api' ]]; then
    metadata_struct=$(aws --no-verify-ssl s3api head-object --bucket "$2" --key "$3") || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error copying object to bucket: $error"
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
    log 2 "put object command requires command type, source, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 's3api' ]] || [[ $1 == 's3' ]]; then
    # shellcheck disable=SC2086
    error=$(aws --no-verify-ssl s3 cp "$(dirname "$2")" s3://"$3" --recursive --exclude="*" --include="$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    # shellcheck disable=SC2086
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put $2 "s3://$3/" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    # shellcheck disable=SC2086
    error=$(mc --insecure cp $2 "$MC_ALIAS"/"$3" 2>&1) || exit_code=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error copying object to bucket: $error"
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
    log 2 "check and put object function requires source, bucket, destination"
    return 1
  fi
  object_exists "s3api" "$2" "$3" || local exists_result=$?
  if [ "$exists_result" -eq 2 ]; then
    log 2 "error checking if object exists"
    return 1
  fi
  if [ "$exists_result" -eq 1 ]; then
    copy_object "$1" "$2" || local copy_result=$?
    if [ "$copy_result" -ne 0 ]; then
      log 2 "error adding object"
      return 1
    fi
  fi
  return 0
}

remove_insecure_request_warning() {
  if [[ $# -ne 1 ]]; then
    log 2 "remove insecure request warning requires input lines"
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

# check if object info (etag) is accessible
# param:  path of object
# return 0 for yes, 1 for no, 2 for error
object_is_accessible() {
  if [ $# -ne 2 ]; then
    log 2 "object accessibility check missing bucket and/or key"
    return 2
  fi
  local exit_code=0
  object_data=$(aws --no-verify-ssl s3api head-object --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    log 2 "Error obtaining object data: $object_data"
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
    log 2 "object ACL command missing object name"
    return 1
  fi
  local exit_code=0
  acl=$(aws --no-verify-ssl s3api get-object-acl --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    log 2 "Error getting object ACLs: $acl"
    return 1
  fi
  export acl
}

# copy a file to/from S3
# params:  source, destination
# return 0 for success, 1 for failure
copy_file() {
  if [ $# -ne 2 ]; then
    log 2 "copy file command requires src and dest"
    return 1
  fi

  local result
  error=$(aws --no-verify-ssl s3 cp "$1" "$2") || result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error copying file: $error"
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