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

source ./tests/commands/put_object.sh

multipart_upload_s3api_complete_from_bucket() {
  if ! check_param_count "multipart_upload_s3api_complete_from_bucket" "bucket, copy source, part count" 3 $#; then
    return 1
  fi
  parts="["
  for ((i = 1; i <= $3; i++)); do
    # shellcheck disable=SC2154
    if ! upload_part_copy "$1" "$2-copy" "$upload_id" "$2" "$i"; then
      log 2 "error uploading part $i"
      return 1
    fi
    # shellcheck disable=SC2154
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $3 ]]; then
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

multipart_upload_from_bucket() {
  if ! check_param_count "multipart_upload_from_bucket" "bucket, copy source, key, part count" 4 $#; then
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

  if ! create_multipart_upload_rest "$1" "$2-copy"; then
    log 2 "error running first multipart upload"
    return 1
  fi

  if ! multipart_upload_s3api_complete_from_bucket "$1" "$2" "$4"; then
    log 2 " error completing multipart upload from bucket"
    return 1
  fi
  return 0
}

split_and_put_file() {
  if ! check_param_count "split_and_put_file" "bucket, key, copy source, part count" 4 $#; then
    return 1
  fi
  if ! split_file "$3" "$4"; then
    log 2 "error splitting file"
    return 1
  fi
  for ((i=0;i<$4;i++)) {
    log 5 "key: $2, file info: $(ls -l "$3"-"$i")"
    if ! put_object "s3api" "$3-$i" "$1" "$2-$i"; then
      log 2 "error copying object"
      return 1
    fi
  }
  return 0
}

multipart_upload_from_bucket_range() {
  if ! check_param_count "multipart_upload_from_bucket_range" "bucket, copy source, key, part count, range" 5 $#; then
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

  if ! create_multipart_upload_rest "$1" "$2-copy"; then
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

multipart_upload_custom() {
  if ! check_param_count_gt "bucket, key, file, part count, optional additional parameters" 4 $$; then
    return 1
  fi

  # shellcheck disable=SC2086 disable=SC2048
  if ! multipart_upload_before_completion_custom "$1" "$2" "$3" "$4" ${*:5}; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  log 5 "upload ID: $upload_id, parts: $parts"
  if ! complete_multipart_upload "$1" "$2" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

multipart_upload() {
  if ! check_param_count "multipart_upload" "bucket, key, file, part count" 4 $#; then
    return 1
  fi

  if ! multipart_upload_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  if ! complete_multipart_upload "$1" "$2" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

# perform a multi-part upload
# params:  bucket, key, source file location, number of parts
# return 0 for success, 1 for failure
multipart_upload_with_params() {
  if ! check_param_count "multipart_upload_with_params" "bucket, key, file, part count, content type, metadata, hold status, lock mode, retain until date, tagging" 10 $#; then
    return 1
  fi
  log 5 "1: $1, 2: $2, 3: $3, 4: $4, 5: $5, 6: $6, 7: $7, 8: $8, 9: $9, 10: ${10}"

  if ! multipart_upload_before_completion_with_params "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi
  log 5 "Upload parts:  $parts"

  if ! complete_multipart_upload "$1" "$2" "$upload_id" "$parts"; then
    log 2 "Error completing upload"
    return 1
  fi
  return 0
}

run_and_verify_multipart_upload_with_valid_range() {
  if ! check_param_count "run_and_verify_multipart_upload_with_valid_range" "bucket, key, 5MB file" 3 $#; then
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

create_upload_part_copy_rest() {
  if ! check_param_count "create_upload_part_copy_rest" "bucket, key, >20MB file" 3 $#; then
    return 1
  fi
  if ! split_and_put_file "$1" "$2" "$3" 4; then
    log 2 "error splitting and putting file"
    return 1
  fi
  if ! create_multipart_upload_rest "$1" "$2"; then
    log 2 "error creating upload and getting ID"
    return 1
  fi
  parts_payload=""
  for ((i=0; i<=3; i++)); do
    part_number=$((i+1))
    if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" PART_NUMBER="$part_number" UPLOAD_ID="$upload_id" PART_LOCATION="$1/$2-$i" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/upload_part_copy.sh); then
      # shellcheck disable=SC2154
      log 2 "error uploading part $i: $result"
      return 1
    fi
    log 5 "result: $result"
    if [ "$result" != "200" ]; then
      log 2 "error uploading part $i: $(cat "$TEST_FILE_FOLDER/response.txt")"
      return 1
    fi
    if ! etag=$(xmllint --xpath '//*[local-name()="ETag"]/text()' "$TEST_FILE_FOLDER/response.txt" 2>&1); then
      log 2 "error retrieving etag: $etag"
      return 1
    fi
    parts_payload+="<Part><ETag>$etag</ETag><PartNumber>$part_number</PartNumber></Part>"
  done
  if ! complete_multipart_upload_rest "$1" "$2" "$upload_id" "$parts_payload"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

create_upload_finish_wrong_etag() {
  if ! check_param_count "create_upload_finish_wrong_etag" "bucket, key" 2 $#; then
    return 1
  fi

  etag="gibberish"
  part_number=1
  if ! create_multipart_upload_rest "$1" "$2"; then
    log 2 "error creating upload and getting ID"
    return 1
  fi
  parts_payload="<Part><ETag>$etag</ETag><PartNumber>$part_number</PartNumber></Part>"
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$upload_id" PARTS="$parts_payload" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/complete_multipart_upload.sh); then
    log 2 "error completing multipart upload: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "complete multipart upload returned code $result: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  if ! error=$(xmllint --xpath '//*[local-name()="Error"]' "$TEST_FILE_FOLDER/result.txt" 2>&1); then
    log 2 "error retrieving error info: $error"
    return 1
  fi
  echo -n "$error" > "$TEST_FILE_FOLDER/error.txt"
  if ! check_xml_element "$TEST_FILE_FOLDER/error.txt" "InvalidPart" "Code"; then
    log 2 "code mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/error.txt" "$upload_id" "UploadId"; then
    log 2 "upload ID mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/error.txt" "$part_number" "PartNumber"; then
    log 2 "part number mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/error.txt" "$etag" "ETag"; then
    log 2 "etag mismatch"
    return 1
  fi
  return 0
}

setup_multipart_upload_with_params() {
  if ! check_param_count "setup_multipart_upload_with_params" "bucket, key" 2 $#; then
    return 1
  fi
  os_name="$(uname)"
  if [[ "$os_name" == "Darwin" ]]; then
    now=$(date -u +"%Y-%m-%dT%H:%M:%S")
    later=$(date -j -v +20S -f "%Y-%m-%dT%H:%M:%S" "$now" +"%Y-%m-%dT%H:%M:%S")
  else
    now=$(date +"%Y-%m-%dT%H:%M:%S")
    later=$(date -d "$now 20 seconds" +"%Y-%m-%dT%H:%M:%S")
  fi

  if ! create_test_files "$2"; then
    log 2 "error creating test file"
    return 1
  fi

  if ! result=$(dd if=/dev/urandom of="$TEST_FILE_FOLDER/$2" bs=20M count=1 2>&1); then
    log 2 "error creating large file: $result"
    return 1
  fi

  if ! bucket_cleanup_if_bucket_exists "$BUCKET_ONE_NAME"; then
    log 2 "error cleaning up bucket"
    return 1
  fi
  # in static bucket config, bucket will still exist
  if ! bucket_exists "$BUCKET_ONE_NAME"; then
    if ! create_bucket_object_lock_enabled "$BUCKET_ONE_NAME"; then
      log 2 "error creating bucket with object lock enabled"
      return 1
    fi
  fi
  log 5 "later in function: $later"
  echo "$later"
  return 0
}
