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
  if ! head_object_rest_expect_success "$1" "$2" "" "200"; then
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
  if ! head_object_rest_expect_success_callback "$1" "$2" "CHECKSUM=true" "parse_head_checksum"; then
    log 2 "error calling HeadObject command"
    return 1
  fi
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
  content_length=$(grep "Content-Length:" "$1" | awk '{print $2}' | tr -d '\r')
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
  if ! head_object_rest_expect_success_callback "$3" "$4" "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2" "parse_content_length"; then
    log 2 "error getting object size"
    return 1
  fi
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
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_for_header_key_and_value "$1" "$header_key" "$header_value"; then
    log 2 "error checking header key '$header_key' and value '$header_value'"
    return 1
  fi
  return 0
}

head_object_check_header_key_and_value() {
  if ! check_param_count_v2 "bucket, key, expected key, expected value" 4 $#; then
    return 1
  fi
  header_key="$3"
  header_value="$4"
  if ! send_rest_go_command_callback "200" "check_header_key_and_value" "-bucketName" "$1" "-objectKey" "$2" \
    "-method" "HEAD"; then
      log 2 "error with head object command or callback"
      return 1
  fi
  return 0
}
