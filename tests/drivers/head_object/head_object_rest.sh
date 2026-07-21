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

get_etag_rest() {
  if ! check_param_count_v2 "bucket name, object key" 2 $#; then
    return 1
  fi
  if ! head_object_rest_expect_success_callback "$1" "$2" "" "parse_etag"; then
    log 2 "error calling HeadObject command"
    return 1
  fi
  return 0
}

parse_etag() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  log 5 "head object data: $(cat "$1")"
  etag_value=$(grep "E[Tt]ag:" "$1" | sed -n 's/E[Tt]ag: "\([^"]*\)"/\1/p' | tr -d '\r')
  echo "$etag_value"
}

verify_object_not_found() {
  if ! check_param_count_v2 "bucket name, key" 2 $#; then
    return 1
  fi
  if ! head_object_rest_expect_error "$1" "$2" "" "404" "Not Found"; then
    return 1
  fi
  return 0
}

verify_object_exists() {
  if ! check_param_count_v2 "bucket name, key" 2 $#; then
    return 1
  fi
  if ! head_object_rest_expect_success "$1" "$2" ""; then
    log 2 "error sending HeadObject command and verifying existence"
    return 1
  fi
  return 0
}

check_checksum_rest() {
  if ! check_param_count_v2 "bucket, file, expected checksum, header key" 4 $#; then
    return 1
  fi
  header_key="$4"

  local response
  if ! response=$(head_object_rest_expect_success_callback "$1" "$2" "CHECKSUM=true" "parse_head_checksum" 2>&1); then
    log 2 "error calling HeadObject command: $response"
    return 1
  fi

  head_checksum="$response"
  if [ "$3" != "$head_checksum" ]; then
    log 2 "'checksum mismatch (head '$head_checksum', local '$3')"
    return 1
  fi
  return 0
}

parse_head_checksum() {
  if ! check_param_count_v2 "file" 1 $#; then
    return 1
  fi
  head_checksum=$(grep -i "$header_key" "$1" | awk '{print $2}' | sed 's/\r$//')
  echo "$head_checksum"
  return 0
}

verify_checksum_doesnt_exist() {
  if ! check_param_count_v2 "file" 1 $#; then
    return 1
  fi
  head_checksum=$(grep -i "$header_key" "$1" | awk '{print $2}' | sed 's/\r$//')
  if [ "$head_checksum" != "" ]; then
    log 2 "head checksum shouldn't be returned, is $head_checksum"
    return 1
  fi
}

parse_content_length() {
  if ! check_param_count_v2 "file" 1 $#; then
    return 1
  fi
  content_length="$(grep "Content-Length:" "$1" | awk '{print $2}' | tr -d '\r')"
  echo "$content_length"
  return 0
}

check_checksum_rest_sha256() {
  if ! check_param_count_v2 "bucket, file, local file" 3 $#; then
    return 1
  fi
  file_checksum="$(sha256sum "$3" | awk '{print $1}' | xxd -r -p | base64)"
  if ! check_checksum_rest "$1" "$2" "$file_checksum" "x-amz-checksum-sha256"; then
    log 2 "error checking sha256 checksum"
    return 1
  fi
  return 0
}

check_checksum_rest_crc32() {
  if ! check_param_count_v2 "bucket, file, local file" 3 $#; then
    return 1
  fi
  file_checksum="$(gzip -c -1 "$3" | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
  if ! check_checksum_rest "$1" "$2" "$file_checksum" "x-amz-checksum-crc32"; then
    log 2 "error checking crc32 checksum"
    return 1
  fi
  return 0
}

head_object_without_and_with_checksum() {
  if ! check_param_count_v2 "bucket, file" 2 $#; then
    return 1
  fi
  header_key="x-amz-checksum-sha256"
  if ! head_object_rest_expect_success_callback "$1" "$2" "" "verify_checksum_doesnt_exist"; then
    log 2 "error verifying HeadObject checksum doesn't exist"
    return 1
  fi
  if ! head_object_rest_expect_success_callback "$1" "$2" "CHECKSUM=true" "parse_head_checksum"; then
    log 2 "error verifying checksum exists"
    return 1
  fi
  return 0
}

check_default_checksum() {
  if ! check_param_count_v2 "bucket, file, local file" 3 $#; then
    return 1
  fi
  header_key="x-amz-checksum-crc64nvme"
  if ! head_object_rest_expect_success_callback "$1" "$2" "CHECKSUM=true" "parse_head_checksum"; then
    log 2 "error verifying HeadObject checksum doesn't exist"
    return 1
  fi
  log 5 "checksum: $head_checksum"
  default_checksum="$head_checksum"
  if ! head_object_rest_expect_success_callback "$1" "$2" "CHECKSUM_TYPE=crc64nvme CHECKSUM=true" "parse_head_checksum"; then
    log 2 "error verifying HeadObject checksum doesn't exist"
    return 1
  fi
  if [ "$head_checksum" != "$default_checksum" ]; then
    log 2 "checksum mismatch (crc64nvme:  '$head_checksum', default:  '$default_checksum')"
    return 1
  fi
  return 0
}

get_object_size_with_user() {
  if ! check_param_count_v2 "username, password, bucket, key" 4 $#; then
    return 1
  fi

  local response
  if ! response=$(head_object_rest_expect_success_callback "$3" "$4" "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2" "parse_content_length" 2>&1); then
    log 2 "error getting object size: $response"
    return 1
  fi

  content_length="$response"
  log 5 "file size: $content_length"
  echo "$content_length"
  return 0
}

check_metadata_key_case() {
  if ! check_param_count_v2 "bucket name, test file, expected mixed-case key, expected value" 4 $#; then
    return 1
  fi
  mixed_case_key="$3"
  expected_value="$4"
  if ! head_object_rest_expect_success_callback "$1" "$2" "" "check_metadata"; then
    log 2 "error checking metadata"
    return 1
  fi
  return 0
}

check_metadata() {
  log 5 "data: $(cat "$1")"
  meta_line=$(grep -i "x-amz-meta" "$1")
  log 5 "meta line: $meta_line"
  meta_value=$(echo -n "$meta_line" | awk '{print $2}' | sed "s/\r//")
  if [ "$meta_value" != "$expected_value" ]; then
    log 2 "expected metadata value of '$expected_value', was '$meta_value'"
    return 1
  fi
  meta_key=$(echo -n "$meta_line" | awk '{print $1}' | sed "s/://")
  lowercase_key=$(printf '%s' "$mixed_case_key" | tr '[:upper:]' '[:lower:]')
  if [ "$meta_key" != "x-amz-meta-${lowercase_key}" ]; then
    log 2 "expected metadata key of '$lowercase_key', was '$meta_key"
    return 1
  fi
  return 0
}

check_header_key_and_value() {
  if ! check_param_count_v2 "data file, header key, header value" 3 $#; then
    return 1
  fi
  if ! check_for_header_key_and_value "$1" "$2" "$3"; then
    log 2 "error checking header key '$2' and value '$3'"
    return 1
  fi
  return 0
}

head_object_check_header_key_and_value() {
  if ! check_param_count_v2 "bucket, key, expected key, expected value" 4 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_header_key_and_value" "-bucketName" "$1" "-objectKey" "$2" \
    "-method" "HEAD" "--" "$3" "$4"; then
      log 2 "error with head object command or callback"
      return 1
  fi
  return 0
}

check_header_partial_content_response() {
  if ! check_param_count_v2 "header data, part number, full object size, part size" 4 $#; then
    return 1
  fi
  log 5 "header: $(cat "$1")"
  starting_byte=$((($2-1)*$4))
  ending_byte=$(($2*$4-1))
  if [ "$3" -lt "$ending_byte" ]; then
    ending_byte="$(($3-1))"
  fi
  content_range_string="bytes $starting_byte-$ending_byte/$3"
  if ! result=$(check_for_header_key_and_value "$1" "Content-Range" "$content_range_string" 2>&1); then
    log 2 "error checking for header key and value: $result"
    return 1
  fi
  return 0
}

get_delete_marker_and_verify_405() {
  if ! check_param_count_v2 "bucket, key" 2 $#; then
    return 1
  fi
  local bucket="$1" key="$2"
  local response versions_data version_id file_name response_code

  if ! response=$(list_object_versions_rest "$bucket" 2>&1); then
    log 2 "error listing REST object versions"
    return 1
  fi
  versions_data="$response"
  log 5 "versions: $versions_data"

  if ! response=$(xmllint --xpath "//*[local-name()=\"DeleteMarker\"]/*[local-name()=\"VersionId\"]/text()" - <<< "$versions_data" 2>&1); then
    log 2 "error getting XML value: $version_id"
    return 1
  fi
  version_id="$response"

  if ! response=$(get_file_name 2>&1); then
    log 2 "error getting file name: $response"
    return 1
  fi
  file_name="$response"

  if ! response=$(OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$bucket" OBJECT_KEY="$key" VERSION_ID="$version_id" ./tests/rest_scripts/head_object.sh); then
    log 2 "error getting result: $response"
    return 1
  fi
  response_code="$response"

  if [ "$response_code" != "405" ]; then
    log 2 "expected '405', was '$response_code' ($(cat "$TEST_FILE_FOLDER/$file_name"))"
    return 1
  fi
  return 0
}

parse_checksum_and_file_size() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  local key value lowercase_key checksum_algorithm checksum checksum_type file_size

  while IFS=$': \r' read -r key value; do
    lowercase_key=${key,,}
    if [[ "$lowercase_key" == "x-amz-checksum-type" ]]; then
      checksum_type="$value"
    elif [[ "$lowercase_key" == "x-amz-checksum-"* ]]; then
      checksum_algorithm="${lowercase_key/x-amz-checksum-/}"
      checksum="$value"
    elif [[ "$lowercase_key" == "content-length" ]]; then
      file_size="$value"
    fi
  done <<< "$(grep -aE '^.+: .+$' "$1")"

  echo "${checksum_algorithm:-none} ${checksum:-none} ${checksum_type:-none} ${file_size:-none}"
  return 0
}

get_checksum_and_file_size() {
  if ! check_param_count_v2 "bucket name, object key" 2 $#; then
    return 1
  fi
  local response

  if ! response=$(send_rest_go_command_callback "200" "parse_checksum_and_file_size" "-method" "HEAD" "-bucketName" "$1" "-objectKey" "$2" "-signedParams" "x-amz-checksum-mode:ENABLED" 2>&1); then
    log 2 "error sending HeadObject command and getting checksum and file size: $response"
    return 1
  fi
  echo "$response"
  return 0
}

# return 3 for error, 2 for skip, 1 for mismatch, 0 for match
check_quick_compare() {
  if ! check_param_count_v2 "local file, bucket name, object key" 3 $#; then
    return 1
  fi
  local response local_file_size checksum_algorithm remote_checksum checksum_type remote_key_size

  if [ -z "$QUICK_COMPARE_SIZE" ]; then
    log 5 "no QUICK_COMPARE_SIZE env param"
    return 2
  fi

  if ! response=$(get_file_size "$1" 2>&1); then
    log 2 "error getting file size: $response"
    return 1
  fi
  local_file_size="$response"

  if [ "$local_file_size" -le "$QUICK_COMPARE_SIZE" ]; then
    log 5 "file size '$local_file_size' less than quick compare size '$QUICK_COMPARE_SIZE'"
    return 2
  fi

  if ! response=$(get_checksum_and_file_size "$2" "$3" 2>&1); then
    log 2 "error getting checksum and file size: $response"
    return 3
  fi
  log 5 "RESPONSE: $response"
  read -r checksum_algorithm remote_checksum checksum_type remote_key_size <<< "$response"

  if [ "$remote_checksum" == "none" ] || [ "$checksum_algorithm" == "none" ] || [ "$checksum_type" != "FULL_OBJECT" ] || [ "$remote_key_size" == "none" ]; then
    log 5 "skipping calcuation, no checksum or checksum algorithm, wrong checksum type, or key size missing"
    return 2
  fi

  if [ "$local_file_size" -ne "$remote_key_size" ]; then
    log 2 "file size mismatch ('$local_file_size' locally, '$remote_key_size' remotely)"
    return 1
  fi

  if ! local_checksum=$(DATA_FILE="$1" CHECKSUM_TYPE="$checksum_algorithm" TEST_FILE_FOLDER="$TEST_FILE_FOLDER" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
    log 2 "error calculating checksum: $local_checksum"
    return 3
  fi
  if [ "$remote_checksum" != "$local_checksum" ]; then
    log 2 "checksum mismatch ('$local_checksum' locally, '$remote_checksum' remotely)"
    return 1
  fi
  return 0
}
