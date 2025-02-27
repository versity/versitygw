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

check_checksum_invalid_or_incorrect() {
  if [ $# -ne 6 ]; then
    log 2 "'check_sha256_invalid_or_incorrect' requires data file, bucket name, key, checksum type, checksum, expected error"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" CHECKSUM_TYPE="$4" CHECKSUM="$5" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected response code of '400', was '$result' (response: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/result.txt" "$6" "Error" "Message"; then
    log 2 "xml error message mismatch"
    return 1
  fi
  return 0
}

put_object_rest_checksum() {
  if [ $# -ne 4 ]; then
    log 2 "'put_object_rest_sha256_checksum' requires data file, bucket name, key, checksum type"
    return 1
  fi
  # shellcheck disable=SC2097,SC2098
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" CHECKSUM_TYPE="$4" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  log 5 "result: $(cat "$TEST_FILE_FOLDER/result.txt")"
  return 0
}

put_object_rest_sha256_invalid() {
  if [ $# -ne 3 ]; then
    log 2 "'put_object_rest_sha256_invalid' requires data file, bucket name, key"
    return 1
  fi
  if ! check_checksum_invalid_or_incorrect "$1" "$2" "$3" "sha256" "dummy" "Value for x-amz-checksum-sha256 header is invalid."; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}

put_object_rest_sha256_incorrect() {
  if [ $# -ne 3 ]; then
    log 2 "'put_object_rest_sha256_invalid' requires data file, bucket name, key"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    error_message="The SHA256 you specified did not match the calculated checksum."
  else
    error_message="The sha256 you specified did not match the calculated checksum."
  fi
  incorrect_checksum="$(echo -n "dummy" | sha256sum | awk '{print $1}' | xxd -r -p | base64)"
  if ! check_checksum_invalid_or_incorrect "$1" "$2" "$3" "sha256" "$incorrect_checksum" "$error_message"; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}

put_object_rest_chunked_payload_type_without_content_length() {
  if [ $# -ne 3 ]; then
    log 2 "'put_object_rest_diff_payload_type' requires data file, bucket name, key"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$2" OBJECT_KEY="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" PAYLOAD="STREAMING-AWS4-HMAC-SHA256-PAYLOAD" ./tests/rest_scripts/put_object.sh 2>&1); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "411" ]; then
    log 2 "expected response code of '411', was '$result' ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}

put_object_rest_crc32_incorrect() {
  if [ $# -ne 3 ]; then
    log 2 "'put_object_rest_crc32_incorrect' requires data file, bucket name, key"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    error_message="The CRC32 you specified did not match the calculated checksum."
  else
    error_message="The crc32 you specified did not match the calculated checksum."
  fi
  incorrect_checksum="$(echo -n "dummy" | gzip -c -1 | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
  if ! check_checksum_invalid_or_incorrect "$1" "$2" "$3" "crc32" "$incorrect_checksum" "$error_message"; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}

put_object_rest_crc64nvme_incorrect() {
  if [ $# -ne 3 ]; then
    log 2 "'put_object_rest_crc64nvme_incorrect' requires data file, bucket name, key"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    error_message="The CRC64NVME you specified did not match the calculated checksum."
  else
    error_message="The crc64nvme you specified did not match the calculated checksum."
  fi
  if ! incorrect_checksum=$(DATA_FILE=<(echo -n "dummy") TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_crc64nvme.sh 2>&1); then
    log 2 "error calculating checksum: $incorrect_checksum"
    return 1
  fi
  if ! check_checksum_invalid_or_incorrect "$1" "$2" "$3" "crc64nvme" "$incorrect_checksum" "$error_message"; then
    log 2 "error checking checksum"
    return 1
  fi
  return 0
}
