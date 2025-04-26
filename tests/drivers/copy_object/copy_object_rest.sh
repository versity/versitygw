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

attempt_copy_object_to_directory_with_same_name() {
  if [ $# -ne 3 ]; then
    log 2 "'attempt_copy_object_to_directory_with_same_name' requires bucket name, key name, copy source"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2/" COPY_SOURCE="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/copy_object.sh); then
    log 2 "error copying object: $result"
    return 1
  fi
  if [ "$result" != "409" ]; then
    log 2 "expected '409', was '$result'"
    return 1
  fi
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/result.txt" "ObjectParentIsFile" "Object parent already exists as a file"; then
    log 2 "error checking XML"
    return 1
  fi
  return 0
}

copy_object_invalid_copy_source() {
  if [ $# -ne 1 ]; then
    log 2 "'copy_object_invalid_copy_source' requires bucket name"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="dummy-copy" COPY_SOURCE="dummy" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/copy_object.sh); then
    log 2 "error copying object: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected '400', was '$result' $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  if ! check_xml_element_contains "$TEST_FILE_FOLDER/result.txt" "InvalidArgument" "Error" "Code"; then
    log 2 "error checking XML error code"
    return 1
  fi
  return 0
}

copy_object_copy_source_and_payload() {
  if [ $# -ne 3 ]; then
    log 2 "'copy_object_copy_source_and_payload' requires bucket name, source key, and local data file"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="${2}-copy" COPY_SOURCE="$1/$2" DATA_FILE="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/copy_object.sh); then
    log 2 "error copying object: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected '400', was '$result' $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  log 5 "result: $(cat "$TEST_FILE_FOLDER/result.txt")"
  if ! check_xml_element_contains "$TEST_FILE_FOLDER/result.txt" "InvalidRequest" "Error" "Code"; then
    log 2 "error checking XML error code"
    return 1
  fi
  return 0
}
