#!/usr/bin/env bats

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

# params:  username, password, bucket, expected key, expected value
# return 0 for success, 1 for failure
get_and_check_bucket_tags_with_user() {
  log 6 "get_and_check_bucket_tags"
  if ! check_param_count_v2 "username, password, bucket, expected key, expected value" 5 $#; then
    return 1
  fi
  if ! get_bucket_tagging_with_user "$1" "$2" "$3"; then
    log 2 "error retrieving bucket tagging"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "TAGS: $tags"
  if ! tag=$(echo "$tags" | jq -r ".TagSet[0]" 2>&1); then
    log 2 "error getting tag: $tag"
    return 1
  fi
  if ! key=$(echo "$tag" | jq -r ".Key" 2>&1); then
    log 2 "error getting key: $key"
    return 1
  fi
  if [ "$key" != "$4" ]; then
    log 2 "key mismatch ($key, $4)"
    return 1
  fi
  if ! value=$(echo "$tag" | jq -r ".Value" 2>&1); then
    log 2 "error getting value: $value"
    return 1
  fi
  if [ "$value" != "$5" ]; then
    log 2 "value mismatch ($value, $5)"
    return 1
  fi
  return 0
}

# params:  bucket, expected tag key, expected tag value
# fail on error
get_and_check_bucket_tags() {
  if ! check_param_count_v2 "bucket, expected key, expected value" 3 $#; then
    return 1
  fi
  if ! get_and_check_bucket_tags_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2" "$3"; then
    log 2 "error getting and checking bucket tags with user"
    return 1
  fi
  return 0
}

add_verify_bucket_tags_rest() {
  if ! check_param_count_v2 "bucket, expected key, expected value" 3 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" TAG_KEY="$2" TAG_VALUE="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_bucket_tagging.sh); then
    log 2 "error putting bucket tags: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    log 2 "expected response code of '204', was '$result' (error: $(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/bucket_tagging.txt" ./tests/rest_scripts/get_bucket_tagging.sh); then
    log 2 "error listing bucket tags: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' (error: $(cat "$TEST_FILE_FOLDER/bucket_tagging.txt"))"
    return 1
  fi
  log 5 "tags: $(cat "$TEST_FILE_FOLDER/bucket_tagging.txt")"
  if ! key=$(xmllint --xpath '//*[local-name()="Key"]/text()' "$TEST_FILE_FOLDER/bucket_tagging.txt" 2>&1); then
    log 2 "error retrieving key: $key"
    return 1
  fi
  if [ "$key" != "$2" ]; then
    log 2 "key mismatch (expected '$2', actual '$key')"
    return 1
  fi
  if ! value=$(xmllint --xpath '//*[local-name()="Value"]/text()' "$TEST_FILE_FOLDER/bucket_tagging.txt" 2>&1); then
    log 2 "error retrieving value: $value"
    return 1
  fi
  if [ "$value" != "$3" ]; then
    log 2 "value mismatch (expected '$3', actual '$value')"
    return 1
  fi
  return 0
}

verify_no_bucket_tags_rest() {
  if ! check_param_count_v2 "bucket" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OUTPUT_FILE="$TEST_FILE_FOLDER/bucket_tagging.txt" ./tests/rest_scripts/get_bucket_tagging.sh); then
    log 2 "error listing bucket tags: $result"
    return 1
  fi
  if [ "$result" != "404" ]; then
    log 2 "expected response code of '404', was '$result' (error: $(cat "$TEST_FILE_FOLDER/bucket_tagging.txt"))"
    return 1
  fi
  return 0
}
