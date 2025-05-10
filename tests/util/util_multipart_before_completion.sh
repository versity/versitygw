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
  if [ $# -ne 5 ]; then
    log 2 "'create_upload_and_test_parts_listing' requires test file, policy_file, user id, username, password"
    return 1
  fi
  if ! multipart_upload_before_completion_with_user "$BUCKET_ONE_NAME" "$1" "$TEST_FILE_FOLDER/$1" 4 "$4" "$5"; then
    log 2 "error creating multipart upload with user"
    return 1
  fi

  # shellcheck disable=SC2154
  if ! list_parts_with_user "$4" "$5" "$BUCKET_ONE_NAME" "$1" "$upload_id"; then
    log 2 "list parts with user failed despite initiator request"
    return 1
  fi
  if ! initiator=$(echo -n "$listed_parts" | jq -r '.Initiator.DisplayName' 2>&1); then
    log 2 "error getting initiator: $initiator"
    return 1
  fi
  if [ "$initiator" != "$3" ]; then
    log 2 "expected initator of '$3', was '$initiator'"
    return 1
  fi
  if ! part_count=$(echo -n "$listed_parts" | jq -r '.Parts | length' 2>&1); then
    log 2 "error getting part count: $part_count"
    return 1
  fi
  if [ "$part_count" != "4" ]; then
    log 2 "expected returned part count of '4', was '$part_count'"
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

  if ! create_multipart_upload_rest "$1" "$2"; then
    log 2 "error creating multpart upload"
    return 1
  fi

  if ! create_multipart_upload_rest "$1" "$3"; then
    log 2 "error creating multpart upload two"
    return 1
  fi

  if ! list_multipart_uploads "$1"; then
    log 2 "error listing uploads"
    return 1
  fi
  return 0
}

multipart_upload_before_completion() {
  if [ $# -ne 4 ]; then
    log 2 "multipart upload pre-completion requires bucket, key, file, part count"
    return 1
  fi
  if ! multipart_upload_before_completion_with_user "$1" "$2" "$3" "$4" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"; then
    log 2 "error uploading multipart before completion"
    return 1
  fi
  return 0
}

# perform all parts of a multipart upload before completion command
# params:  bucket, key, file to split and upload, number of file parts to upload
# return:  0 for success, 1 for failure
multipart_upload_before_completion_with_user() {
  if [ $# -ne 6 ]; then
    log 2 "multipart upload pre-completion command missing bucket, key, file, part count, username, password"
    return 1
  fi

  if ! split_file "$3" "$4"; then
    log 2 "error splitting file"
    return 1
  fi

  if ! create_multipart_upload_s3api_with_user "$1" "$2" "$5" "$6"; then
    log 2 "error creating multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    # shellcheck disable=SC2154
    if ! upload_part_with_user "$1" "$2" "$upload_id" "$3" "$i" "$5" "$6"; then
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

  if ! result=$(split_file "$3" "$4" 2>&1); then
    log 2 "error splitting file: $result"
    return 1
  fi

  if ! create_multipart_upload_s3api_params "$1" "$2" "$5" "$6" "$7" "$8" "$9" "${10}"; then
    log 2 "error creating multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
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

multipart_upload_before_completion_custom() {
  if [ $# -lt 4 ]; then
    log 2 "multipart upload custom command missing bucket, key, file, part count, and/or optional params"
    return 1
  fi

  if ! result=$(split_file "$3" "$4" 2>&1); then
    log 2 "error splitting file"
    return 1
  fi

  # shellcheck disable=SC2086 disable=SC2048
  if ! create_multipart_upload_custom "$1" "$2" ${*:5}; then
    log 2 "error creating multipart upload"
    return 1
  fi
  log 5 "upload ID: $upload_id"

  parts="["
  for ((i = 1; i <= $4; i++)); do
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

multipart_upload_range_too_large() {
  if ! check_param_count_v2 "bucket, key, file location" 3 $#; then
    return 1
  fi
  if multipart_upload_from_bucket_range "$1" "$2" "$3" 4 "bytes=0-1000000000"; then
    log 2 "multipart upload succeeded despite overly large range"
    return 1
  fi
  # shellcheck disable=SC2154
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

upload_part_copy_without_upload_id_or_part_number() {
  if [ $# -ne 7 ]; then
    log 2 "'upload_part_copy_without_upload_id_or_part_number' requires bucket name, key, part number, upload ID, response code, error code, message"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" PART_NUMBER="$3" UPLOAD_ID="$4" PART_LOCATION="$BUCKET_ONE_NAME/$2-1" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/upload_part_copy.sh); then
    # shellcheck disable=SC2154
    log 2 "error uploading part $i: $result"
    return 1
  fi
  log 5 "result: $result"
  if [ "$result" != "$5" ]; then
    log 2 "expected '$5', was '$result' ($(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  log 5 "error:  $(cat "$TEST_FILE_FOLDER/response.txt")"
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/response.txt" "$6" "$7"; then
    log 2 "error checking XML response"
    return 1
  fi
}

upload_part_check_etag_header() {
  if [ $# -ne 3 ]; then
    log 2 "'upload_part_check_etag_header' requires bucket name, key, upload ID"
    return 1
  fi
  if ! etag=$(upload_part_rest "$1" "$2" "$3" 1 2>&1); then
    log 2 "error getting etag: $etag"
    return 1
  fi
  if ! [[ "$etag" =~ ^\"[0-9a-f]+\" ]]; then
    log 2 "etag pattern mismatch, etag ($etag) should be hex string surrounded by quotes"
    return 1
  fi
  return 0
}

upload_part_copy_check_etag_header() {
  if [ $# -ne 3 ]; then
    log 2 "'upload_part_copy_check_etag_header' requires bucket, destination file, part location"
    return 1
  fi
  if ! upload_id=$(create_multipart_upload_rest "$1" "$2" 2>&1); then
    log 2 "error creating upload and getting ID: $upload_id"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" PART_NUMBER="1" UPLOAD_ID="$upload_id" PART_LOCATION="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/upload_part_copy.sh); then
    # shellcheck disable=SC2154
    log 2 "error uploading part: $result"
    return 1
  fi
  if ! etag=$(get_element_text "$TEST_FILE_FOLDER/response.txt" "CopyPartResult" "ETag"); then
    log 2 "error getting etag"
    return 1
  fi
  log 5 "etag: $etag"
  if ! [[ "$etag" =~ ^\"[0-9a-f]+\" ]]; then
    log 2 "etag pattern mismatch, etag ($etag) should be hex string surrounded by quotes"
    return 1
  fi
  return 0
}

upload_part_without_part_number() {
  if [ $# -ne 2 ]; then
    log 2 "'upload_part_without_upload_id' requires bucket name, key"
    return 1
  fi
  if ! create_multipart_upload_rest "$1" "$2"; then
    log 2 "error creating multpart upload"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" DATA_FILE="$TEST_FILE_FOLDER/$2" PART_NUMBER="" UPLOAD_ID="$upload_id" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/upload_part.sh); then
    # shellcheck disable=SC2154
    log 2 "error uploading part $i: $result"
    return 1
  fi
  if [ "$result" != "405" ]; then
    log 2 "expected '405', was '$result' ($(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  return 0
}

upload_part_without_upload_id() {
  if [ $# -ne 2 ]; then
    log 2 "'upload_part_without_part_number' requires bucket name, key"
    return 1
  fi
  if ! create_multipart_upload_rest "$1" "$2"; then
    log 2 "error creating multpart upload"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" DATA_FILE="$TEST_FILE_FOLDER/$2" PART_NUMBER="1" UPLOAD_ID="" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/upload_part.sh 2>&1); then
    # shellcheck disable=SC2154
    log 2 "error uploading part $i: $result"
    return 1
  fi
  if [ "$result" != "405" ]; then
    log 2 "expected '405', was '$result' ($(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  return 0
}
