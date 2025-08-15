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

put_bucket_acl_success_or_access_denied() {
  if ! check_param_count_v2 "bucket, acl file, username, password, expect success" 5 $#; then
    return 1
  fi
  if [ "$5" == "true" ]; then
    if ! put_bucket_acl_rest_with_user "$3" "$4" "$1" "$2"; then
      log 2 "expected PutBucketAcl to succeed, didn't"
      return 1
    fi
  else
    if ! put_bucket_acl_rest_expect_error "$1" "$2" "AWS_ACCESS_KEY_ID=$3 AWS_SECRET_ACCESS_KEY=$4" "403" "AccessDenied" "Access Denied"; then
      log 2 "expected PutBucketAcl access denied"
      return 1
    fi
  fi
  return 0
}

put_invalid_acl_rest_verify_failure() {
  if [ $# -ne 2 ]; then
    log 2 "'put_invalid_acl_rest_verify_failure' requires bucket name, ACL file"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" ACL_FILE="$2" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/put_bucket_acl.sh); then
    log 2 "error attempting to put bucket acl: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "response returned code: $result (error: $(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  if ! error_code=$(xmllint --xpath '//*[local-name()="Code"]/text()' "$TEST_FILE_FOLDER/response.txt" 2>&1); then
    log 2 "error getting display name: $error_code"
    return 1
  fi
  if [ "$error_code" != "MalformedACLError" ]; then
    log 2 "invalid error code, expected 'MalformedACLError', was '$error_code'"
    return 1
  fi
  return 0
}

# param: bucket name
# return 0 for success, 1 for failure
check_ownership_rule_and_reset_acl() {
  if [ $# -ne 1 ]; then
    log 2 "'check_ownership_rule_and_reset_acl' requires bucket name"
    return 1
  fi
  if ! object_ownership_rule=$(get_bucket_ownership_controls_rest "$1" 2>&1); then
    log 2 "error getting bucket ownership controls"
    return 1
  fi
  log 5 "ownership rule: $object_ownership_rule"
  if [[ $object_ownership_rule != "BucketOwnerEnforced" ]] && ! reset_bucket_acl "$1"; then
    log 2 "error resetting bucket ACL"
    return 1
  fi
}
