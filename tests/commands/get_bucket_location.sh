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

get_bucket_location() {
  record_command "get-bucket-location" "client:$1"
  if [[ $# -ne 2 ]]; then
    log 2 "get bucket location command requires command type, bucket name"
    return 1
  fi
  get_result=0
  if [[ $1 == 's3api' ]]; then
    get_bucket_location_aws "$2" || get_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_bucket_location_s3cmd "$2" || get_result=$?
  elif [[ $1 == 'mc' ]]; then
    get_bucket_location_mc "$2" || get_result=$?
  else
    log 2 "command type '$1' not implemented for get_bucket_location"
    return 1
  fi
  if [[ $get_result -ne 0 ]]; then
    return 1
  fi
  location=$(echo "$location_json" | jq -r '.LocationConstraint')
}

get_bucket_location_aws() {
  record_command "get-bucket-location" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "get bucket location (aws) requires bucket name"
    return 1
  fi
  location_json=$(send_command aws --no-verify-ssl s3api get-bucket-location --bucket "$1") || location_result=$?
  if [[ $location_result -ne 0 ]]; then
    echo "error getting bucket location: $location"
    return 1
  fi
  bucket_location=$(echo "$location_json" | jq -r '.LocationConstraint')
  return 0
}

get_bucket_location_s3cmd() {
  record_command "get-bucket-location" "client:s3cmd"
  if [[ $# -ne 1 ]]; then
    echo "get bucket location (s3cmd) requires bucket name"
    return 1
  fi
  info=$(send_command s3cmd --no-check-certificate info "s3://$1") || results=$?
  if [[ $results -ne 0 ]]; then
    log 2 "error getting bucket location: $location"
    return 1
  fi
  bucket_location=$(echo "$info" | grep -o 'Location:.*' | awk '{print $2}')
  return 0
}

get_bucket_location_mc() {
  record_command "get-bucket-location" "client:mc"
  if [[ $# -ne 1 ]]; then
    log 2 "get bucket location (mc) requires bucket name"
    return 1
  fi
  info=$(send_command mc --insecure stat "$MC_ALIAS/$1") || results=$?
  if [[ $results -ne 0 ]]; then
    log 2 "error getting s3cmd info: $info"
    return 1
  fi
  # shellcheck disable=SC2034
  bucket_location=$(echo "$info" | grep -o 'Location:.*' | awk '{print $2}')
  return 0
}