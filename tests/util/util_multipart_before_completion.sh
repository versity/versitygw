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

source ./tests/drivers/list_parts/list_parts_s3api.sh

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
  if ! check_param_count_v2 "bucket, key, file, part count" 4 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" part_count="$4"
  local part_num segment_idx segment locally_calculated_etag
  local -a segment_array locally_calculated_etags

  if ! response=$(split_file "$file" "$part_count" 2>&1); then
    log 2 "error splitting file: $response"
    return 1
  fi
  read -r -a segment_array <<< "$response"
  log 5 "calculated etag: $(openssl dgst -md5 "${segment_array[0]}" | awk '{print $NF}')"

  if ! response=$(create_multipart_upload_s3api "$bucket" "$key" 2>&1); then
    log 2 "error creating multpart upload: $response"
    return 1
  fi
  upload_id="$response"

  for ((part_num = 1; part_num <= part_count; part_num++)); do
    segment_idx=$((part_num - 1))
    segment="${segment_array[$segment_idx]}"
    locally_calculated_etag="\"$(openssl dgst -md5 "$segment" | awk '{print $NF}')\""
    if ! response=$(upload_part "$bucket" "$key" "$upload_id" "$segment" "$part_num" 2>&1); then
      log 2 "error uploading part '$part_num': $response"
      return 1
    fi
    etag="$response"
    if [ "$etag" != "$locally_calculated_etag" ]; then
      log 2 "local/returned etag mismatch, expected '$locally_calculated_etag', actual '$etag'"
      return 1
    fi
    locally_calculated_etags+=("$locally_calculated_etag")
  done
  if ! list_and_check_part_numbers_and_etags "$bucket" "$key" "$upload_id" "${locally_calculated_etags[@]}"; then
    log 2 "error listing and checking part numbers and etags"
    return 1
  fi
  return 0
}

parse_parts_and_etags() {
  if ! check_param_count_v2 "parts string, part ID" 2 $#; then
    return 1
  fi
  local parts="$1" part_id="$2"
  local response part part_number etag

  # shellcheck disable=SC2154
  if ! response=$(echo "$parts" | grep -v "InsecureRequestWarning" | jq -r ".[$part_id]" 2>&1); then
    log 2 "error getting part: $part"
    return 1
  fi
  part="$response"

  if ! response=$(echo "$part" | jq ".PartNumber" 2>&1); then
    log 2 "error parsing part number: $response"
    return 1
  fi
  part_number="$response"
  if [ -z "$part_number" ]; then
    log 2 "error:  blank part number"
    return 1
  fi

  if ! response=$(echo "$part" | jq ".ETag" 2>&1); then
    log 2 "error parsing etag: $response"
    return 1
  fi
  etag="$response"
  if [ -z "$etag" ]; then
    log 2 "error:  blank etag"
    return 1
  fi
  # shellcheck disable=SC2004
  printf '%s %s\n' "$part_number" "$etag"
  return 0
}

compare_parts_to_listed_parts() {
  if ! check_param_count_v2 "part number" 1 $#; then
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
  if ! check_param_count_v2 "bucket, key, file, part count" 4 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" part_count="$4"
  local response listed_parts
  local -a upload_id_and_part_list

  if ! response=$(multipart_upload_before_completion "$bucket" "$key" "$file" "$part_count" 2>&1); then
    log 2 "error performing pre-completion multipart upload: $response"
    return 1
  fi
  mapfile -t upload_id_and_part_list <<< "$response"

  if ! response=$(list_parts "$bucket" "$key" "${upload_id_and_part_list[0]}" 2>&1); then
    log 2 "Error listing multipart upload parts: $response"
    return 1
  fi
  listed_parts="$response"
  printf '%s\n' "$listed_parts"
  return 0
}

create_list_check_multipart_uploads() {
  if ! check_param_count_v2 "bucket, two keys" 3 $#; then
    return 1
  fi
  local response uploads raw_uploads key_one key_two second_match

  if ! response=$(create_and_list_multipart_uploads "$1" "$2" "$3" 2>&1); then
    log 2 "error creating and listing multipart uploads"
    return 1
  fi
  uploads="$response"

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
    if [ "$2" != "$key_two" ]; then
      log 2 "Key mismatch ('$2' doesn't match '$key_one' or '$key_two')"
      return 1
    fi
    second_match="$key_one"
  else
    second_match="$key_two"
  fi
  if [[ "$3" != "$second_match" ]]; then
    log 2 "Key mismatch (expected '$3', actual '$second_match')"
    return 1
  fi
  return 0
}

# list unfinished multipart uploads
# params:  bucket, key one, key two
# export current two uploads on success, return 1 for error
create_and_list_multipart_uploads() {
  if ! check_param_count_v2 "bucket, two keys" 3 $#; then
    return 1
  fi
  local response

  if ! response=$(create_multipart_upload_rest "$1" "$2" "" "" 2>&1); then
    log 2 "error creating multipart upload one: $response"
    return 1
  fi

  if ! response=$(create_multipart_upload_rest "$1" "$3" "" "" 2>&1); then
    log 2 "error creating multipart upload two: $response"
    return 1
  fi

  if ! response=$(list_multipart_uploads "$1" 2>&1); then
    log 2 "error listing uploads: $response"
    return 1
  fi
  echo "$response"
  return 0
}

multipart_upload_before_completion() {
  if ! check_param_count_v2 "bucket, key, file, part count" 4 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" part_count="$4"
  local response

  if ! response=$(multipart_upload_before_completion_with_user "$bucket" "$key" "$file" "$part_count" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" 2>&1); then
    log 2 "error uploading multipart before completion: $response"
    return 1
  fi
  echo "$response"
  return 0
}

# perform all parts of a multipart upload before completion command
# params:  bucket, key, file to split and upload, number of file parts to upload
# return:  0 for success, 1 for failure
multipart_upload_before_completion_with_user() {
  if ! check_param_count_v2 "bucket, key, file, part count, username, password" 6 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" part_count="$4" username="$5" password="$6"
  local response upload_id parts idx etag
  local -a segment_array

  if ! response=$(split_file "$file" "$part_count" 2>&1); then
    log 2 "error splitting file: $response"
    return 1
  fi
  read -r -a segment_array <<< "$response"
  log 5 "calculated etag: $(openssl dgst -md5 ${segment_array[0]} | awk '{print $NF}')"

  if ! response=$(create_multipart_upload_s3api_with_user "$bucket" "$key" "$username" "$password" 2>&1); then
    log 2 "error creating multpart upload: $response"
    return 1
  fi
  upload_id="$response"

  parts="["
  for ((idx = 1; idx <= part_count; idx++)); do
    # shellcheck disable=SC2154
    if ! response=$(upload_part_with_user "$bucket" "$key" "$upload_id" "${segment_array[$((idx-1))]}" "$idx" "$username" "$password" 2>&1); then
      log 2 "error uploading part '$idx': $response"
      return 1
    fi
    etag="$response"

    parts+="{\"ETag\": $etag, \"PartNumber\": $idx}"
    if [[ $idx -ne $part_count ]]; then
      parts+=","
    fi
  done
  parts+="]"
  printf '%s\n%s\n' "$upload_id" "$parts"
  return 0
}

multipart_upload_before_completion_with_params() {
  if ! check_param_count_v2 "bucket, key, file, part count, content type, metadata, hold status, lock mode, retain until date, tagging" 10 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" part_count="$4" content_type="$5" \
    metadata="$6" hold_status="$7" lock_mode="$8" retain_until_date="$9" tagging="${10}"
  local response upload_id parts idx etag
  local -a segment_array

  if ! response=$(split_file "$file" "$part_count" 2>&1); then
    log 2 "error splitting file: $result"
    return 1
  fi
  read -r -a segment_array <<< "$response"

  if ! response=$(create_multipart_upload_s3api_params "$bucket" "$key" "$content_type" "$metadata" "$hold_status" "$lock_mode" \
      "$retain_until_date" "$tagging" 2>&1); then
    log 2 "error creating multipart upload: $response"
    return 1
  fi
  upload_id="$response"

  parts="["
  for ((idx = 1; idx <= part_count; idx++)); do
    if ! response=$(upload_part "$bucket" "$key" "$upload_id" "${segment_array[$((idx-1))]}" "$idx" 2>&1); then
      log 2 "error uploading part '$idx': '$response'"
      return 1
    fi
    etag="$response"

    parts+="{\"ETag\": $etag, \"PartNumber\": $idx}"
    if [[ $idx -ne $part_count ]]; then
      parts+=","
    fi
  done
  parts+="]"

  printf '%s\n%s\n' "$upload_id" "$parts"
  return 0
}

multipart_upload_before_completion_custom() {
  if [ $# -lt 4 ]; then
    log 2 "multipart upload custom command missing bucket, key, file, part count, and/or optional params"
    return 1
  fi

  if ! segments=$(split_file "$3" "$4" 2>&1); then
    log 2 "error splitting file"
    return 1
  fi
  read -r -a segment_array <<< "$segments"

  # shellcheck disable=SC2086 disable=SC2048
  if ! create_multipart_upload_custom "$1" "$2" ${*:5}; then
    log 2 "error creating multipart upload"
    return 1
  fi
  log 5 "upload ID: $upload_id"

  parts="["
  for ((i = 1; i <= $4; i++)); do
    if ! upload_part "$1" "$2" "$upload_id" "${segment_array[$i]}" "$i"; then
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
  local bucket="$1" key="$2" file_location="$3"
  local response

  if response=$(multipart_upload_from_bucket_range "$bucket" "$key" "$file_location" 4 "bytes=0-1000000000" 2>&1); then
    log 2 "multipart upload succeeded despite overly large range: $response"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$response" != *"Range specified is not valid"* ]] && [[ "$response" != *"InvalidRange"* ]]; then
    log 2 "unexpected error: $response"
    return 1
  fi
  return 0
}

list_and_check_upload() {
  if ! check_param_count_ge_le "bucket, key, upload ID" 2 3 $#; then
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
  if ! check_param_count_v2 "bucket, key, upload ID, part number, part" 5 $#; then
    return 1
  fi

  local response
  if ! response=$(upload_part_rest "$1" "$2" "$3" "$4" "$5" 2>&1); then
    log 2 "error getting etag: $response"
    return 1
  fi
  etag="$response"

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

  local response
  if ! response=$(create_multipart_upload_rest "$1" "$2" "" "parse_upload_id" 2>&1); then
    log 2 "error creating upload and getting ID: $response"
    return 1
  fi
  upload_id="$response"

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" PART_NUMBER="1" UPLOAD_ID="$upload_id" PART_LOCATION="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" ./tests/rest_scripts/upload_part_copy.sh); then
    # shellcheck disable=SC2154
    log 2 "error uploading part: $result"
    return 1
  fi
  if ! response=$(get_element_text "$TEST_FILE_FOLDER/$file_name" "CopyPartResult" "ETag" 2>&1); then
    log 2 "error getting etag: $response"
    return 1
  fi
  etag="$response"

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
  if ! create_multipart_upload_rest "$1" "$2" "" "parse_upload_id"; then
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
  if ! create_multipart_upload_rest "$1" "$2" "" "parse_upload_id"; then
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
