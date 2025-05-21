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

get_bucket_ownership_controls() {
  if [[ -n "$SKIP_BUCKET_OWNERSHIP_CONTROLS" ]]; then
    log 5 "Skipping get bucket ownership controls"
    return 0
  fi

  record_command "get-bucket-ownership-controls" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "'get bucket ownership controls' command requires bucket name"
    return 1
  fi

  raw_bucket_ownership_controls=""
  if ! raw_bucket_ownership_controls=$(send_command aws --no-verify-ssl s3api get-bucket-ownership-controls --bucket "$1" 2>&1); then
    log 2 "error getting bucket ownership controls: $raw_bucket_ownership_controls"
    return 1
  fi

  log 5 "Raw bucket Ownership Controls:  $raw_bucket_ownership_controls"
  bucket_ownership_controls=$(echo "$raw_bucket_ownership_controls" | grep -v "InsecureRequestWarning")
  return 0
}

get_bucket_ownership_controls_rest() {
  if ! check_param_count "get_bucket_ownership_controls_rest" "bucket" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OUTPUT_FILE="$TEST_FILE_FOLDER/ownershipControls.txt" ./tests/rest_scripts/get_bucket_ownership_controls.sh); then
    log 2 "error getting bucket ownership controls: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "GetBucketOwnershipControls returned response code: $result, reply:  $(cat "$TEST_FILE_FOLDER/ownershipControls.txt")"
    return 1
  fi
  log 5 "controls: $(cat "$TEST_FILE_FOLDER/ownershipControls.txt")"
  if ! rule=$(xmllint --xpath '//*[local-name()="ObjectOwnership"]/text()' "$TEST_FILE_FOLDER/ownershipControls.txt" 2>&1); then
    log 2 "error getting ownership rule: $rule"
    return 1
  fi
  echo "$rule"
}

get_object_ownership_rule() {
  if [[ -n "$SKIP_BUCKET_OWNERSHIP_CONTROLS" ]]; then
    log 5 "Skipping get bucket ownership controls"
    return 0
  fi

  if [[ $# -ne 1 ]]; then
    log 2 "'get object ownership rule' command requires bucket name"
    return 1
  fi
  if ! get_bucket_ownership_controls "$1"; then
    log 2 "error getting bucket ownership controls"
    return 1
  fi
  if ! object_ownership_rule=$(echo "$bucket_ownership_controls" | jq -r ".OwnershipControls.Rules[0].ObjectOwnership" 2>&1); then
    log 2 "error getting object ownership rule: $object_ownership_rule"
    return 1
  fi
  log 5 "object ownership rule: $object_ownership_rule"
  return 0
}