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

# param: bucket name
# return 0 for success, 1 for error
abort_all_multipart_uploads() {
  if [ $# -ne 1 ]; then
    log 2 "'abort_all_multipart_uploads' requires bucket name"
    return 1
  fi
  if ! list_multipart_uploads "$1"; then
    log 2 "error listing multipart uploads"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "UPLOADS: $uploads"
  if ! upload_set=$(echo "$uploads" | grep -v "InsecureRequestWarning" | jq -c '.Uploads[]' 2>&1); then
    if [[ $upload_set == *"Cannot iterate over null"* ]]; then
      return 0
    else
      log 2 "error getting upload set: $upload_set"
      return 1
    fi
  fi
  log 5 "UPLOAD SET: $upload_set"
  for upload in $upload_set; do
    log 5 "UPLOAD: $upload"
    if ! upload_id=$(echo "$upload" | jq -r ".UploadId" 2>&1); then
      log 2 "error getting upload ID: $upload_id"
      return 1
    fi
    log 5 "upload ID: $upload_id"
    if ! key=$(echo "$upload" | jq -r ".Key" 2>&1); then
      log 2 "error getting key: $key"
      return 1
    fi
    log 5 "Aborting multipart upload for key: $key, UploadId: $upload_id"
    if ! abort_multipart_upload "$1" "$key" "$upload_id"; then
      log 2 "error aborting multipart upload"
      return 1
    fi
  done
}
