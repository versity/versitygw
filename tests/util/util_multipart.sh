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

create_upload_and_test_parts_listing() {
  if [ $# -ne 2 ]; then
    log 2 "'create_upload_and_test_parts_listing' requires test file, policy_file"
    return 1
  fi
  if ! create_multipart_upload_with_user "$BUCKET_ONE_NAME" "$1" "$USERNAME_ONE" "$PASSWORD_ONE"; then
    log 2 "error creating multipart upload with user"
    return 1
  fi

  # shellcheck disable=SC2154
  if list_parts_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$1" "$upload_id"; then
    log 2 "list parts with user succeeded despite lack of policy permissions"
    return 1
  fi

  if ! setup_policy_with_single_statement "$TEST_FILE_FOLDER/$2" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:ListMultipartUploadParts" "arn:aws:s3:::$BUCKET_ONE_NAME/*"; then
    log 2 "error setting up policy"
    return 1
  fi

  if ! put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$2"; then
    log 2 "error putting policy"
    return 1
  fi

  if ! list_parts_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$1" "$upload_id"; then
    log 2 "error listing parts after policy add"
    return 1
  fi
  return 0
}

start_multipart_upload_list_check_parts() {
  if [ $# -ne 3 ]; then
    log 2 "'start_multipart_upload_and_list_parts' requires bucket, key, original source"
    return 1
  fi
  if ! start_multipart_upload_and_list_parts "$1" "$2" "$3" 4; then
    log 2 "error starting upload"
    return 1
  fi

  declare -a parts_map
  # shellcheck disable=SC2154
  log 5 "parts: $parts"
  for i in {0..3}; do
    if ! parse_parts_and_etags "$i"; then
      log 2 "error parsing part $i"
      return 1
    fi
  done
  if [[ ${#parts_map[@]} -eq 0 ]]; then
    log 2 "error loading multipart upload parts to check"
    return 1
  fi

  for i in {0..3}; do
    if ! compare_parts_to_listed_parts "$i"; then
      log 2 "error comparing parts to listed parts"
      return 1
    fi
  done
  return 0
}

parse_parts_and_etags() {
  if [ $# -ne 1 ]; then
    log 2 "'parse_parts_and_etags' requires part id"
    return 1
  fi
  local part_number
  local etag
  # shellcheck disable=SC2154
  if ! part=$(echo "$parts" | grep -v "InsecureRequestWarning" | jq -r ".[$i]" 2>&1); then
    log 2 "error getting part: $part"
    return 1
  fi
  if ! part_number=$(echo "$part" | jq ".PartNumber" 2>&1); then
    log 2 "error parsing part number: $part_number"
    return 1
  fi
  if [[ $part_number == "" ]]; then
    log 2 "error:  blank part number"
    return 1
  fi
  if ! etag=$(echo "$part" | jq ".ETag" 2>&1); then
    log 2 "error parsing etag: $etag"
    return 1
  fi
  if [[ $etag == "" ]]; then
    log 2 "error:  blank etag"
    return 1
  fi
  # shellcheck disable=SC2004
  parts_map[$part_number]=$etag
}

compare_parts_to_listed_parts() {
  if [ $# -ne 1 ]; then
    log 2 "'compare_parts_to_listed_parts' requires part number"
    return 1
  fi
  local part_number
  local etag
  # shellcheck disable=SC2154
  if ! listed_part=$(echo "$listed_parts" | grep -v "InsecureRequestWarning" | jq -r ".Parts[$i]" 2>&1); then
    log 2 "error parsing listed part: $listed_part"
    return 1
  fi
  if ! part_number=$(echo "$listed_part" | jq ".PartNumber" 2>&1); then
    log 2 "error parsing listed part number: $part_number"
    return 1
  fi
  if ! etag=$(echo "$listed_part" | jq ".ETag" 2>&1); then
    log 2 "error getting listed etag: $etag"
    return 1
  fi
  if [[ ${parts_map[$part_number]} != "$etag" ]]; then
    log 2 "error:  etags don't match (part number: $part_number, etags ${parts_map[$part_number]},$etag)"
    return 1
  fi
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

create_list_check_multipart_uploads() {
  if [ $# -ne 3 ]; then
    log 2 "list multipart uploads command requires bucket and two keys"
    return 1
  fi
  if ! create_and_list_multipart_uploads "$1" "$2" "$3"; then
    log 2 "error creating and listing multipart uploads"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "Uploads:  $uploads"
  raw_uploads=$(echo "$uploads" | grep -v "InsecureRequestWarning")
  if ! key_one=$(echo "$raw_uploads" | jq -r '.Uploads[0].Key' 2>&1); then
    log 2 "error getting key one: $key_one"
    return 1
  fi
  if ! key_two=$(echo "$raw_uploads" | jq -r '.Uploads[1].Key' 2>&1); then
    log 2 "error getting key two: $key_two"
    return 1
  fi
  if [[ "$2" != "$key_one" ]]; then
    log 2 "Key mismatch ($2, $key_one)"
    return 1
  fi
  if [[ "$3" != "$key_two" ]]; then
    log 2 "Key mismatch ($3, $key_two)"
    return 1
  fi
  return 0
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
    log 2 "error listing uploads"
    return 1
  fi
  return 0
}

multipart_upload_from_bucket() {
  if [ $# -ne 4 ]; then
    log 2 "multipart upload from bucket command missing bucket, copy source, key, and/or part count"
    return 1
  fi

  if ! split_file "$3" "$4"; then
    log 2 "error splitting file"
    return 1
  fi

  for ((i=0;i<$4;i++)) {
    log 5 "key: $3"
    if ! put_object "s3api" "$3-$i" "$1" "$2-$i"; then
      log 2 "error copying object"
      return 1
    fi
  }

  if ! create_multipart_upload "$1" "$2-copy"; then
    log 2 "error running first multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    if ! upload_part_copy "$1" "$2-copy" "$upload_id" "$2" "$i"; then
      log 2 "error uploading part $i"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  if ! error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}' 2>&1); then
    log 2 "Error completing upload: $error"
    return 1
  fi
  return 0
}

multipart_upload_from_bucket_range() {
  if [ $# -ne 5 ]; then
    log 2 "multipart upload from bucket with range command requires bucket, copy source, key, part count, and range"
    return 1
  fi
  if ! split_file "$3" "$4"; then
    log 2 "error splitting file"
    return 1
  fi
  for ((i=0;i<$4;i++)) {
    log 5 "key: $3, file info: $(ls -l "$3"-"$i")"
    if ! put_object "s3api" "$3-$i" "$1" "$2-$i"; then
      log 2 "error copying object"
      return 1
    fi
  }

  if ! create_multipart_upload "$1" "$2-copy"; then
    log 2 "error running first multpart upload"
    return 1
  fi
  parts="["
  for ((i = 1; i <= $4; i++)); do
    if ! upload_part_copy_with_range "$1" "$2-copy" "$upload_id" "$2" "$i" "$5"; then
      # shellcheck disable=SC2154
      log 2 "error uploading part $i: $upload_part_copy_error"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"
  if ! error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}'); then
    log 2 "Error completing upload: $error"
    return 1
  fi
  return 0
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

create_upload_and_get_id_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'create_upload_and_get_id_rest' requires bucket, key"
    return 1
  fi
  if ! result=$(COMMAND_LOG=$COMMAND_LOG BUCKET_NAME=$1 OBJECT_KEY=$2 OUTPUT_FILE="$TEST_FILE_FOLDER/output.txt" ./tests/rest_scripts/create_multipart_upload.sh); then
    log 2 "error creating multipart upload: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "error:  response code: $result, output: $(cat "$TEST_FILE_FOLDER/output.txt")"
    return 1
  fi
  log 5 "multipart upload create info: $(cat "$TEST_FILE_FOLDER/output.txt")"
  if ! upload_id=$(xmllint --xpath '//*[local-name()="UploadId"]/text()' "$TEST_FILE_FOLDER/output.txt" 2>&1); then
    log 2 "error getting upload ID: $upload_id"
    return 1
  fi
  log 5 "upload ID: $upload_id"
  return 0
}

multipart_upload_range_too_large() {
  if [ $# -ne 3 ]; then
    log 2 "'multipart_upload_range_too_large' requires bucket name, key, file location"
    return 1
  fi
  if multipart_upload_from_bucket_range "$1" "$2" "$3" 4 "bytes=0-1000000000"; then
    log 2 "multipart upload succeeded despite overly large range"
    return 1
  fi
  log 5 "error: $upload_part_copy_error"
  if [[ $upload_part_copy_error != *"Range specified is not valid"* ]] && [[ $upload_part_copy_error != *"InvalidRange"* ]]; then
    log 2 "unexpected error: $upload_part_copy_error"
    return 1
  fi
  return 0
}

list_and_check_upload() {
  if [ $# -lt 2 ]; then
    log 2 "'list_and_check_upload' requires bucket, key, upload ID (optional)"
    return 1
  fi
  if ! uploads=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/uploads.txt" ./tests/rest_scripts/list_multipart_uploads.sh); then
    log 2 "error listing multipart uploads before upload: $result"
    return 1
  fi
  if ! upload_count=$(xmllint --xpath 'count(//*[local-name()="Upload"])' "$TEST_FILE_FOLDER/uploads.txt" 2>&1); then
    log 2 "error retrieving upload count: $upload_count"
    return 1
  fi
  if [[ (( $# == 2 ) && ( $upload_count != 0 )) ]]; then
    log 2 "upload count mismatch (expected 0, actual $upload_count)"
    return 1
  elif [[ (( $# == 3 ) && ( $upload_count != 1 )) ]]; then
    log 2 "upload count mismatch (expected 1, actual $upload_count)"
    return 1
  fi
  if [ $# -eq 2 ]; then
    return 0
  fi
  if ! key=$(xmllint --xpath '//*[local-name()="Key"]/text()' "$TEST_FILE_FOLDER/uploads.txt" 2>&1); then
    log 2 "error retrieving key: $key"
    return 1
  fi
  if [ "$key" != "$2" ]; then
    log 2 "key mismatch (expected '$2', actual '$key')"
    return 1
  fi
  if ! upload_id=$(xmllint --xpath '//*[local-name()="UploadId"]/text()' "$TEST_FILE_FOLDER/uploads.txt" 2>&1); then
    log 2 "error retrieving upload ID: $upload_id"
    return 1
  fi
  if [ "$upload_id" != "$3" ]; then
    log 2 "upload ID mismatch (expected '$3', actual '$upload_id')"
    return 1
  fi
  return 0
}

run_and_verify_multipart_upload_with_valid_range() {
  if [ $# -ne 3 ]; then
    log 2 "'run_and_verify_multipart_upload_with_valid_range' requires bucket, key, 5MB file"
    return 1
  fi
  range_max=$((5*1024*1024-1))
  if ! multipart_upload_from_bucket_range "$1" "$2" "$3" 4 "bytes=0-$range_max"; then
    log 2 "error with multipart upload"
    return 1
  fi
  if ! get_object "s3api" "$1" "$2-copy" "$3-copy"; then
    log 2 "error getting object"
    return 1
  fi
  if [[ $(uname) == 'Darwin' ]]; then
    object_size=$(stat -f%z "$3-copy")
  else
    object_size=$(stat --format=%s "$3-copy")
  fi
  if [[ object_size -ne $((range_max*4+4)) ]]; then
    log 2 "object size mismatch ($object_size, $((range_max*4+4)))"
    return 1
  fi
  return 0
}

list_check_multipart_upload_key() {
  if [ $# -ne 4 ]; then
    log 2 "'list_check_multipart_upload_key' requires bucket, username, password, expected key"
    return 1
  fi
  if ! list_multipart_uploads_with_user "$1" "$2" "$3"; then
    log 2 "error listing multipart uploads with user"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "$uploads"
  if ! upload_key=$(echo "$uploads" | grep -v "InsecureRequestWarning" | jq -r ".Uploads[0].Key" 2>&1); then
    log 2 "error parsing upload key from uploads message: $upload_key"
    return 1
  fi
  if [[ "$4" != "$upload_key" ]]; then
    log 2 "upload key doesn't match file marked as being uploaded (expected: '$4', actual: '$upload_key')"
    return 1
  fi
  return 0
}
