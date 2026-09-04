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

calculate_multipart_checksum() {
  if ! check_param_count_gt "checksum type, part count, data file, lowercase algorithm, checksums" 4 $#; then
    return 1
  fi
  local checksum_type="$1" part_count="$2" data_file="$3" lowercase_algorithm="$4" checksums=("${@:5}")
  local response

  log 5 "checksums: ${checksums[*]}"
  if [ "$checksum_type" == "COMPOSITE" ]; then
    if ! response=$(calculate_composite_checksum "$lowercase_algorithm" "${checksums[@]}" 2>&1); then
      log 2 "error calculating checksum: $response"
      return 1
    fi
    checksum="$response-${part_count}"
    echo "$checksum"
    return 0
  fi

  if [ "$checksum_type" != "FULL_OBJECT" ]; then
    log 2 "unrecognized checksum type: '$checksum_type'"
    return 1
  fi
  if ! response=$(DATA_FILE="$data_file" CHECKSUM_TYPE="$lowercase_algorithm" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log 2 "error calculating checksum: $response"
    return 1
  fi
  echo "$response"
  return 0
}

complete_multipart_upload_with_checksum() {
  if ! check_param_count_v2 "bucket, key, file, upload ID, part count, parts payload, checksum type, checksum algorithm, checksum" 9 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3" upload_id="$4" part_count="$5" parts_payload="$6" checksum_type="$7" checksum_algorithm="$8" checksum="$9"
  local response response_file result

  log 5 "checksum algorithm: '$checksum_algorithm'"
  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  response_file="$response"

  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$bucket" OBJECT_KEY="$key" UPLOAD_ID="$upload_id" PARTS="$parts_payload" CHECKSUM_TYPE="$checksum_type" \
      CHECKSUM_ALGORITHM="$checksum_algorithm" CHECKSUM_HASH="$checksum" OUTPUT_FILE="$TEST_FILE_FOLDER/$response_file" ./tests/rest_scripts/complete_multipart_upload.sh); then
    log 2 "error completing multipart upload"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/$response_file"))"
    return 1
  fi
  log 5 "result: $(cat "$TEST_FILE_FOLDER/$response_file")"
  return 0
}

calculate_composite_checksum() {
  log 5 "algorithm: $1, checksums: ${*:2}"
  if ! check_param_count_gt "algorithm, at least two checksums" 3 $#; then
    return 1
  fi
  if ! result=$(truncate -s 0 "$TEST_FILE_FOLDER/all_checksums.bin" 2>&1); then
    log 2 "error truncating file: $result"
    return 1
  fi
  log 5 "checksums: ${*:2}"
  for checksum in "${@:2}"; do
    if ! printf '%s' "$checksum" | base64 -d >> "$TEST_FILE_FOLDER/all_checksums.bin"; then
      log 2 "error calculating binary checksum and adding to file"
      return 1
    fi
  done
  if [ "$1" == "sha256" ]; then
    composite=$(openssl dgst -sha256 -binary "$TEST_FILE_FOLDER/all_checksums.bin" | base64)
  elif [ "$1" == "sha1" ]; then
    composite=$(openssl dgst -sha1 -binary "$TEST_FILE_FOLDER/all_checksums.bin" | base64)
  elif [ "$1" == "crc32" ]; then
    composite="$(gzip -c -1 "$TEST_FILE_FOLDER/all_checksums.bin" | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
  elif [ "$1" == "crc32c" ]; then
    if ! composite=$(CHECKSUM_TYPE="$1" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" DATA_FILE="$TEST_FILE_FOLDER/all_checksums.bin" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
      log 2 "error calculating crc32c checksum: $composite"
      return 1
    fi
  fi
  log 5 "composite: $composite"
  echo "$composite"
  return 0
}

test_multipart_upload_with_checksum() {
  log 6 "test_multipart_upload_with_checksum"
  if ! check_param_count_v2 "checksum type, algorithm" 2 $#; then
    return 1
  fi
  local checksum_type="$1" checksum_algorithm="$2"
  local file_and_bucket bucket_name mp_file_name response checksum

  if ! file_and_bucket=$(setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up file and bucket"
    return 1
  fi
  read -r bucket_name mp_file_name <<< "$file_and_bucket"
  log 5 "file name: $mp_file_name, file info:  $(ls -l "$TEST_FILE_FOLDER/$mp_file_name")"

  if ! response=$(perform_full_multipart_upload_with_checksum_before_completion "$bucket_name" "$mp_file_name" "$checksum_type" "$checksum_algorithm" 2>&1); then
    log 2 "error performing multipart upload with checksum before completion: $response"
    return 1
  fi
  mapfile -t response_lines<<< "$response"
  local lowercase_checksum_algorithm="${response_lines[0]}"
  local upload_id="${response_lines[1]}"
  local checksum_string="${response_lines[2]}"
  local payload_parts="${response_lines[3]}"
  read -r -a checksums <<< "$checksum_string"

  if ! response=$(calculate_multipart_checksum "$1" 2 "$TEST_FILE_FOLDER/$mp_file_name" "$lowercase_checksum_algorithm" "${checksums[@]}" 2>&1); then
    log 2 "error calculating multipart checksum: $response"
    return 1
  fi
  checksum="$response"

  if ! complete_multipart_upload_with_checksum "$bucket_name" "$mp_file_name" "$TEST_FILE_FOLDER/$mp_file_name" "$upload_id" 2 "$payload_parts" "$1" "$2" "$checksum"; then
    log 2 "error completing multipart upload with checksum"
    return 1
  fi
  return 0
}

test_complete_multipart_upload_unneeded_algorithm_parameter() {
  if ! check_param_count_v2 "checksum type, algorithm" 2 $#; then
    return 1
  fi
  local checksum_type="$1" algorithm="$2"
  local file_and_bucket bucket_name mp_file_name
  lcoal -a response_lines

  if ! file_and_bucket=$(setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up file and bucket"
    return 1
  fi
  read -r bucket_name mp_file_name <<< "$file_and_bucket"
  if ! response=$(perform_full_multipart_upload_with_checksum_before_completion "$bucket_name" "$mp_file_name" "$checksum_type" "$algorithm" 2>&1); then
    log 2 "error performing multipart upload with checksum before completion"
    return 1
  fi
  mapfile -t response_lines <<< "$response"
  local upload_id="${response_lines[1]}"
  local parts_payload="${response_lines[3]}"

  if ! complete_multipart_upload_rest_nonexistent_param "$bucket_name" "$mp_file_name" "$upload_id" "$parts_payload"; then
    log 2 "error completing multipart upload with nonexistent param"
    return 1
  fi
  return 0
}

test_complete_multipart_upload_incorrect_checksum() {
  if ! check_param_count_v2 "checksum type, algorithm" 2 $#; then
    return 1
  fi
  local checksum_type="$1" algorithm="$2"
  local response bucket_name mp_file_name checksum
  local -a response_lines

  if ! response=$(setup_bucket_and_large_file_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up file and bucket"
    return 1
  fi
  read -r bucket_name mp_file_name <<< "$response"
  if ! response=$(perform_full_multipart_upload_with_checksum_before_completion "$bucket_name" "$mp_file_name" "$checksum_type" "$algorithm" 2>&1); then
    log 2 "error performing multipart upload with checksum before completion"
    return 1
  fi
  mapfile -t response_lines <<< "$response"
  local lowercase_checksum_algorithm="${response_lines[0]}"
  local upload_id="${response_lines[1]}"
  local checksum_string="${response_lines[2]}"
  local payload_parts="${response_lines[3]}"
  read -r -a checksums <<< "$checksum_string"

  if ! response=$(calculate_multipart_checksum "$checksum_type" 2 "$TEST_FILE_FOLDER/$mp_file_name" "$lowercase_checksum_algorithm" "${checksums[@]}" 2>&1); then
    log 2 "error calculating multipart checksum"
    return 1
  fi
  checksum="$response"

  if ! complete_multipart_upload_rest_incorrect_checksum "$bucket_name" "$mp_file_name" "$upload_id" "$payload_parts" "$checksum_type" "$algorithm" "$checksum"; then
    log 2 "error completing multipart upload with incorrect checksum"
    return 1
  fi
  return 0
}

test_complete_multipart_upload_invalid_checksum() {
  if ! check_param_count_v2 "checksum type, algorithm" 2 $#; then
    return 1
  fi
  local checksum_type="$1" algorithm="$2"
  local file_and_bucket bucket_name mp_file_name response
  local -a response_lines

  if ! file_and_bucket=$(setup_bucket_and_file_v3 "$BUCKET_ONE_NAME" 2>&1); then
    log 2 "error setting up file and bucket"
    return 1
  fi
  read -r bucket_name mp_file_name <<< "$file_and_bucket"
  if ! response=$(perform_full_multipart_upload_with_checksum_before_completion "$bucket_name" "$mp_file_name" "$checksum_type" "$algorithm" 2>&1); then
    log 2 "error performing multipart upload with checksum before completion: $response"
    return 1
  fi
  mapfile -t response_lines <<< "$response"
  local upload_id="${response_lines[1]}"
  local parts_payload="${response_lines[3]}"

  if ! complete_multipart_upload_rest_invalid_checksum "$bucket_name" "$mp_file_name" "$upload_id" "$parts_payload" "$checksum_type" "$algorithm" "wrong"; then
    log 2 "error completing multipart upload with invalid checksum"
    return 1
  fi
  return 0
}

complete_multipart_upload_invalid_object_size_string() {
  if ! check_param_count_v2 "bucket, key, file" 3 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3"
  local response upload_id parts_payload

  if ! response=$(multipart_upload_rest_before_completion "$bucket" "$key" "$file" 2 2>&1); then
    log 2 "error performing multipart upload before completion: $response"
    return 1
  fi
  read -r upload_id parts_payload <<< "$response"
  if ! complete_multipart_upload_rest_expect_error "$bucket" "$key" "$upload_id" "$parts_payload" "MULTIPART_OBJECT_SIZE=size" "400" "InvalidRequest" "Value for x-amz-mp-object-size header is invalid"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

perform_multipart_upload_rest() {
  if  ! check_param_count_v2 "bucket, key, four parts" 6 $#; then
    return 1
  fi
  local bucket="$1" key="$2" four_parts=("${@:3}")

  if ! perform_multipart_upload_rest_variable_parts "$bucket" "$key" "${four_parts[@]}"; then
    return 1
  fi
  return 0
}

upload_check_parts() {
  if ! check_param_count_v2 "bucket, key, list of 4 parts" 6 $#; then
    return 1
  fi
  local bucket="$1" key="$2" four_parts=("${@:3}")
  local upload_id parts_payload

  if ! upload_id=$(create_multipart_upload_rest "$bucket" "$key" "" "parse_upload_id" 2>&1); then
    log 2 "error creating upload: $upload_id"
    return 1
  fi
  if ! check_part_list_rest "$bucket" "$key" "$upload_id" 0; then
    log 2 "error checking part list before part upload"
    return 1
  fi
  if ! parts_payload=$(upload_each_part_and_check "$bucket" "$key" "$upload_id" "${four_parts[@]}" 2>&1); then
    log 2 "error uploading and checking parts: $parts_payload"
    return 1
  fi
  if ! complete_multipart_upload_rest "$bucket" "$key" "$upload_id" "$parts_payload"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

perform_multipart_upload_rest_variable_parts() {
  if ! check_param_count_gt "bucket, key, at least two part locations" 4 $#; then
    return 1
  fi
  local bucket="$1" key="$2" parts=("${@:3}")
  local response upload_id part etag

  if ! response=$(create_multipart_upload_rest "$bucket" "$key" "" "parse_upload_id" 2>&1); then
    log 2 "error creating multipart upload: $response"
    return 1
  fi
  upload_id="$response"

  local parts_payload="" idx=1
  for part in "${parts[@]}"; do
    if ! response=$(upload_part_rest "$bucket" "$key" "$upload_id" "$idx" "$part" 2>&1); then
      log 2 "error uploading part $idx: $response"
      return 1
    fi
    etag="$response"
    parts_payload+="<Part><ETag>$etag</ETag><PartNumber>$idx</PartNumber></Part>"
    idx=$((idx+1))
  done
  log 5 "final payload: $parts_payload"

  if ! complete_multipart_upload_rest "$bucket" "$key" "$upload_id" "$parts_payload"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

complete_multipart_upload_empty_upload_id() {
  if ! check_param_count_v2 "bucket, key, file" 3 $#; then
    return 1
  fi
  local bucket="$1" key="$2" file="$3"
  local response upload_id parts_payload

  if ! response=$(multipart_upload_rest_before_completion "$bucket" "$key" "$file" 2 2>&1); then
    log 2 "error performing multipart upload before completion: $response"
    return 1
  fi
  read -r upload_id parts_payload <<< "$response"
  if ! complete_multipart_upload_rest_expect_error "$bucket" "$key" "" "$parts_payload" "" "404" "NoSuchUpload" "The specified upload does not exist"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

create_upload_part_copy_rest() {
  if ! check_param_count "create_upload_part_copy_rest" "bucket, key, >20MB file" 3 $#; then
    return 1
  fi
  local bucket="$1" key="$2" large_file="$3"
  local response upload_id file_name parts_payload i part_number result etag

  if ! split_and_put_file "$bucket" "$key" "$large_file" 4; then
    log 2 "error splitting and putting file"
    return 1
  fi

  if ! response=$(create_multipart_upload_rest "$bucket" "$key" "" "parse_upload_id" 2>&1); then
    log 2 "error creating upload and getting ID: $response"
    return 1
  fi
  upload_id="$response"

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  parts_payload=""
  for ((i=0; i<=3; i++)); do
    part_number=$((i+1))
    if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$bucket" OBJECT_KEY="$key" PART_NUMBER="$part_number" UPLOAD_ID="$upload_id" PART_LOCATION="${bucket}/${key}-$i" OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" ./tests/rest_scripts/upload_part_copy.sh); then
      # shellcheck disable=SC2154
      log 2 "error uploading part $i: $result"
      return 1
    fi
    log 5 "result: $result"
    if [ "$result" != "200" ]; then
      log 2 "error uploading part $i: $(cat "$TEST_FILE_FOLDER/$file_name")"
      return 1
    fi
    if ! etag=$(xmllint --xpath '//*[local-name()="ETag"]/text()' "$TEST_FILE_FOLDER/$file_name" 2>&1); then
      log 2 "error retrieving etag: $etag"
      return 1
    fi
    parts_payload+="<Part><ETag>$etag</ETag><PartNumber>$part_number</PartNumber></Part>"
  done
  if ! complete_multipart_upload_rest "$bucket" "$key" "$upload_id" "$parts_payload"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

create_upload_finish_wrong_etag() {
  if ! check_param_count "create_upload_finish_wrong_etag" "bucket, key" 2 $#; then
    return 1
  fi
  local bucket="$1" key="$2"
  local etag part_number parts_payload result response result_file error_file

  if ! response=$(get_file_names 2 2>&1); then
    log 2 "error getting file names: $response"
    return 1
  fi
  read -r result_file error_file <<< "$response"

  etag="gibberish"
  part_number=1
  if ! create_multipart_upload_rest "$bucket" "$key" "" "parse_upload_id"; then
    log 2 "error creating upload and getting ID"
    return 1
  fi
  parts_payload="<Part><ETag>$etag</ETag><PartNumber>$part_number</PartNumber></Part>"
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$bucket" OBJECT_KEY="$key" UPLOAD_ID="$upload_id" PARTS="$parts_payload" OUTPUT_FILE="$TEST_FILE_FOLDER/$result_file" ./tests/rest_scripts/complete_multipart_upload.sh); then
    log 2 "error completing multipart upload: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "complete multipart upload returned code $result: $(cat "$TEST_FILE_FOLDER/$result_file")"
    return 1
  fi
  if ! get_xml_data "$TEST_FILE_FOLDER/$result_file" "$TEST_FILE_FOLDER/$error_file"; then
    log 2 "error getting XML data"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/$error_file" "InvalidPart" "Code"; then
    log 2 "code mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/$error_file" "$upload_id" "UploadId"; then
    log 2 "upload ID mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/$error_file" "$part_number" "PartNumber"; then
    log 2 "part number mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/$error_file" "$etag" "ETag"; then
    log 2 "etag mismatch"
    return 1
  fi
  return 0
}
