#!/usr/bin/env bats

# Copyright 2026 Versity Software
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

source ./tests/drivers/rest.sh

check_cors_404_content_type_header_and_bucket_name() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! check_for_header_key_and_value "$1" "Content-Type" "application/xml"; then
    log 2 "error checking Content-Type header and value"
    return 1
  fi
  if ! check_specific_argument_name_and_value "$1"; then
    log 2 "error checking BucketName"
    return 1
  fi
  return 0
}

get_bucket_cors_check_404_header_and_bucket_name() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  argument_name="BucketName"
  argument_value="$1"
  if ! send_rest_go_command_expect_error_callback "404" "NoSuchCORSConfiguration" "The CORS configuration does not exist" \
    "check_cors_404_content_type_header_and_bucket_name" "-bucketName" "$1" "-query" "cors"; then
      log 2 "error sending get cors command and checking result"
      return 1
  fi
  return 0
}

check_cors_response_data() {
  if ! check_param_count_v2 "data file, allowed origin, allowed method one, allowed method two" 4 $#; then
    return 1
  fi
  local data_file="$1"
  local allowed_origin="$2"
  local allowed_method_one="$3"
  local allowed_method_two="$4"
  
  if ! check_xml_element "$data_file" "$allowed_origin" "CORSConfiguration" "CORSRule" "AllowedOrigin"; then
    log 2 "error checking for allowed origin value of '$allowed_origin'"
    return 1
  fi
  if ! check_if_element_exists "$data_file" "$allowed_method_one" "CORSConfiguration" "CORSRule" "AllowedMethod"; then
    log 2 "error checking if allowed method '$allowed_method_one' exists"
    return 1
  fi
  if ! check_if_element_exists "$data_file" "$allowed_method_two" "CORSConfiguration" "CORSRule" "AllowedMethod"; then
    log 2 "error checking if allowed method '$allowed_method_two' exists"
    return 1
  fi
  return 0
}

get_bucket_cors_check_valid_data() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  allowed_origin="http://example.com"
  allowed_method_one="GET"
  allowed_method_two="PUT"
  payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?><CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><CORSRule><AllowedOrigin>$allowed_origin</AllowedOrigin><AllowedMethod>$allowed_method_one</AllowedMethod><AllowedMethod>$allowed_method_two</AllowedMethod></CORSRule></CORSConfiguration>"
  if ! send_openssl_go_command "200" "-bucketName" "$1" "-query" "cors" "-method" "PUT" "-payload" "$payload" "-contentMD5"; then
    log 2 "error sending PutBucketCors go command"
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_cors_response_data" "-query" "cors" "-bucketName" "$1" -- "$allowed_origin" "$allowed_method_one" "$allowed_method_two"; then
    log 2 "error sending GetCors command or checking response"
    return 1
  fi
  return 0
}