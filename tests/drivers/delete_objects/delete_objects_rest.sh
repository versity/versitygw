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

delete_object_empty_bucket_check_error() {
  if ! file_name=$(get_file_name 2>&1); then
    log 2 "error getting file name: $file_name"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="" ./tests/rest_scripts/delete_objects.sh); then
    log 2 "error deleting objects: $result"
    return 1
  fi
  log 5 "result: $(cat "$TEST_FILE_FOLDER/$file_name")"
  if ! error=$(xmllint --xpath "Error" "$TEST_FILE_FOLDER/$file_name" 2>&1); then
    log 2 "error getting XML error data: $error"
    return 1
  fi
  if ! error_file_name=$(get_file_name 2>&1); then
    log 2 "error getting error file name: $file_name"
    return 1
  fi
  echo -n "$error" > "$TEST_FILE_FOLDER/$error_file_name"
  if ! check_xml_element "$TEST_FILE_FOLDER/$error_file_name" "MethodNotAllowed" "Code"; then
    log 2 "Code mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/$error_file_name" "POST" "Method"; then
    log 2 "Method mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/$error_file_name" "SERVICE" "ResourceType"; then
    log 2 "ResourceType mismatch"
    return 1
  fi
  return 0
}

delete_objects_no_content_md5_header() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  data="<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
    <Object>
       <Key>dontcare</Key>
    </Object>
    <Object>
       <Key>dontcareeither</Key>
    </Object>
  </Delete>"

  if ! file_name=$(get_file_name 2>&1); then
    log 2 "error getting file name: $file_name"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" COMMAND_LOG="$COMMAND_LOG" PAYLOAD="$data" BUCKET_NAME="$1" HAS_CONTENT_MD5="false" ./tests/rest_scripts/delete_objects.sh); then
    log 2 "error deleting objects: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected response code '400', actual '$result' ($(cat "$TEST_FILE_FOLDER/$file_name")"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/$file_name" "InvalidRequest" "Error" "Code"; then
    log 2 "error checking error element"
    return 1
  fi
  return 0
}

delete_objects_verify_success() {
  if ! check_param_count_v2 "bucket name, two object names" 3 $#; then
    return 1
  fi
  data="<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
  <Object>
     <Key>$2</Key>
  </Object>
  <Object>
     <Key>$3</Key>
  </Object>
</Delete>"

  if ! file_name=$(get_file_name 2>&1); then
    log 2 "error getting file name: $file_name"
    return 1
  fi
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/$file_name" COMMAND_LOG="$COMMAND_LOG" PAYLOAD="$data" BUCKET_NAME="$1" ./tests/rest_scripts/delete_objects.sh); then
    log 2 "error deleting objects: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result ($(cat "$TEST_FILE_FOLDER/$file_name"))"
    return 1
  fi
  return 0
}
