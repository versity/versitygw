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

source ./tests/commands/command.sh
source ./tests/logger.sh

# shellcheck disable=SC2153,SC2034
aws_access_key_id="$AWS_ACCESS_KEY_ID"
# shellcheck disable=SC2153,SC2034
aws_secret_access_key="$AWS_SECRET_ACCESS_KEY"

if [ -z "$AWS_ENDPOINT_URL" ]; then
  host="localhost:7070"
else
  # shellcheck disable=SC2034
  host="$(echo "$AWS_ENDPOINT_URL" | awk -F'//' '{print $2}')"
fi

if [ -z "$AWS_REGION" ]; then
  aws_region="us-east-1"
else
  # shellcheck disable=SC2034
  aws_region="$AWS_REGION"
fi

add_command_recording_if_enabled() {
  if [ -n "$COMMAND_LOG" ]; then
    curl_command+=(send_command)
  fi
}

create_canonical_hash_sts_and_signature() {
  # shellcheck disable=SC2154
  canonical_request_hash="$(echo -n "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')"

  # shellcheck disable=SC2154
  year_month_day="$(echo "$current_date_time" | cut -c1-8)"

  if [ $# -eq 0 ]; then
    sts_data="AWS4-HMAC-SHA256
$current_date_time
$year_month_day/$aws_region/s3/aws4_request
$canonical_request_hash"
  else
    sts_data="$1"
  fi

  date_key=$(echo -n "$year_month_day" | openssl dgst -sha256 -mac HMAC -macopt key:"AWS4${aws_secret_access_key}" | awk '{print $2}')
  date_region_key=$(echo -n "$aws_region" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_key" | awk '{print $2}')
  date_region_service_key=$(echo -n "s3" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_region_key" | awk '{print $2}')
  signing_key=$(echo -n "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_region_service_key" | awk '{print $2}')
  # shellcheck disable=SC2034
  signature=$(echo -n "$sts_data" | openssl dgst -sha256 \
                   -mac HMAC \
                   -macopt hexkey:"$signing_key" | awk '{print $2}')

  if [ $# -eq 0 ]; then
    curl_command=()
    add_command_recording_if_enabled
  fi
}

add_parameter() {
  if [ "$#" -lt 2 ]; then
    return
  fi
  if [ "$3" != "" ]; then
    divider="$3"
  else
    divider="&"
  fi
  current_string="$1"
  if [ "$current_string" != "" ]; then
    current_string+="$divider"
  fi
  current_string+="$2"
  echo "$current_string"
}

log_rest() {
  if [ $# -ne 2 ]; then
    return 1
  fi
  if [ "$BATS_TEST_NAME" != "" ]; then
    log_with_stack_ref "$1" "$2" 2
  else
    echo "$2"
  fi
}

add_cr_parameters_and_header_fields() {
  canonical_request+="$line
"
  if [[ "$line" == *":"* ]]; then
    local key="${line%%:*}"
    local value="${line#*:}"
    if [ "$key" == "x-amz-content-sha256" ]; then
      payload="$value"
    fi
    if [[ "$value" != "" ]]; then
      param_list=$(add_parameter "$param_list" "$key" ";")
      header_fields+=(-H "\"$key: $value\"")
    fi
  fi
}

build_canonical_request() {
  if [ $# -lt 0 ]; then
    log_rest 2 "'build_canonical_request' requires parameters"
    return 1
  fi
  canonical_request=""
  param_list=""
  local payload=""
  header_fields=()
  for line in "$@"; do
    add_cr_parameters_and_header_fields
  done
  canonical_request+="
$param_list
$payload"
}
