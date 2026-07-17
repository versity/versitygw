#!/usr/bin/env bash

# Copyright 2025 Versity Software
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

bucket_exists() {
  if ! check_param_count "bucket_exists" "bucket name" 1 $#; then
    return 2
  fi
  local response_code=0
  exists=$(head_bucket_rest "$1" "check_bucket_existence_callback" 2>&1) || response_code=$?
  echo "$exists"
  return "$response_code"
}

check_bucket_existence_callback() {
  if ! check_param_count_v2 "response code, response data" 2 $#; then
    return 1
  fi
  if [ "$1" -eq 200 ]; then
    echo "true"
    return 0
  elif [ "$1" -eq 404 ]; then
    echo "false"
    return 1
  fi
  echo "error checking if bucket exists (data: $2)"
  return 2
}

get_endpoint() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  local data_file="$1"
  local response endpoint

  if ! response=$(get_element_text "$data_file" "Error" "Endpoint" 2>&1); then
    log 2 "error getting endpoint: $response"
    return 1
  fi
  endpoint="$response"
  log 5 "endpoint: $endpoint"
  echo "$endpoint"
  return 0
}

head_bucket_get_endpoint() {
  if ! check_param_count_gt "bucket name, params (optional)" 1 $#; then
    return 1
  fi
  local bucket="$1"
  local response endpoint

  if ! response=$(send_rest_go_command_expect_error_callback "301" "PermanentRedirect" "must be addressed" "get_endpoint" "-bucketName" "$bucket" "${@:2}" 2>&1); then
    if [[ "$response" == *"HTTP/1.1 200 OK"* ]]; then
      echo "$AWS_ENDPOINT_URL"
      return 0
    fi
    log 2 "error getting response: $response"
    return 1
  fi
  log 5 "response: $response"
  endpoint="$response"

  log 5 "returned endpoint: $endpoint"
  echo "https://${endpoint}"
  return 0
}

get_bucket_location_and_endpoint() {
  if ! check_param_count_v2 "bucket" 1 $#; then
    return 1
  fi
  local bucket="$1"
  local response region endpoint_url

  if ! response=$(get_bucket_location_rest "$1" "parse_bucket_location" 2>&1); then
    log 2 "error getting bucket location: $response"
    return 1
  fi
  region="$response"
  if [ "$region" == "" ]; then
    region="us-east-1"
  fi
  if [ "$DIRECT" != "true" ]; then
    echo "$region $AWS_ENDPOINT_URL"
    return 0
  fi

  if ! response=$(AWS_REGION="$region" head_bucket_get_endpoint "$bucket" 2>&1); then
    log 2 "error getting bucket region and endpoint: $response"
    return 1
  fi
  if [ "$response" != "$AWS_ENDPOINT_URL" ]; then
    endpoint_url="https://s3.${region}.amazonaws.com"
  else
    endpoint_url="$AWS_ENDPOINT_URL"
  fi
  echo "$region" "$endpoint_url"
  return 0
}
