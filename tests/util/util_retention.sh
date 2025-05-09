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

# params:  bucket name
# return 0 for success, 1 for error
add_governance_bypass_policy() {
  if [[ $# -ne 2 ]]; then
    log 2 "'add governance bypass policy' command requires client, bucket name"
    return 1
  fi
  cat <<EOF > "$TEST_FILE_FOLDER/policy-bypass-governance.txt"
{
  "Version": "2012-10-17",
  "Statement": [
    {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "s3:BypassGovernanceRetention",
       "Resource": "arn:aws:s3:::$2/*"
    }
  ]
}
EOF
  log 5 "params: $1 $2"
  if ! put_bucket_policy "$1" "$2" "$TEST_FILE_FOLDER/policy-bypass-governance.txt"; then
    log 2 "error putting governance bypass policy"
    return 1
  fi
  return 0
}

# params: bucket, object, possible WORM error after deletion attempt
# return 0 for success, 1 for no WORM protection, 2 for error
check_for_and_remove_worm_protection() {
  if [ $# -ne 3 ]; then
    log 2 "'check_for_and_remove_worm_protection' command requires bucket, object, error"
    return 2
  fi

  if [[ $3 == *"WORM"* ]]; then
    log 5 "WORM protection found"
    if ! put_object_legal_hold "rest" "$1" "$2" "OFF"; then
      log 2 "error removing object legal hold"
      return 2
    fi
    sleep 1
    if [[ $LOG_LEVEL_INT -ge 5 ]]; then
      log_worm_protection "$1" "$2"
    fi
    if ! add_governance_bypass_policy "rest" "$1"; then
      log 2 "error adding new governance bypass policy"
      return 2
    fi
    if ! delete_object_bypass_retention "$1" "$2" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY"; then
      log 2 "error deleting object after legal hold removal"
      return 2
    fi
  else
    log 5 "no WORM protection found"
    return 1
  fi
  return 0
}

# params: bucket name, object
log_worm_protection() {
  if ! get_object_legal_hold "$1" "$2"; then
    log 2 "error getting object legal hold status"
    return
  fi
  # shellcheck disable=SC2154
  log 5 "LEGAL HOLD: $legal_hold"
  if ! get_object_retention "$1" "$2"; then
    log 2 "error getting object retention"
    # shellcheck disable=SC2154
    if [[ $get_object_retention_error != *"NoSuchObjectLockConfiguration"* ]]; then
      return
    fi
  fi
  # shellcheck disable=SC2154
  log 5 "RETENTION: $retention"
}

retention_rest_without_request_body() {
  if [ $# -ne 2 ]; then
    log 2 "'retention_rest_without_request_body' requires bucket name, key"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" OMIT_PAYLOAD="true" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object_retention.sh); then
    log 2 "error: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected '400', was '$result'"
    return 1
  fi
  log 5 "result: $result ($(cat "$TEST_FILE_FOLDER/result.txt"))"
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/result.txt" "MalformedXML" "The XML you provided"; then
    log 2 "error checking xml reply"
    return 1
  fi
  return 0
}
