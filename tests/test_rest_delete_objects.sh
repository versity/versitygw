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

load ./bats-support/load
load ./bats-assert/load

source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/delete_objects/delete_objects_rest.sh
source ./tests/setup.sh

# tags: curl, DeleteObjects, malformed-message
@test "REST - DeleteObjects - missing payload" {
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_expect_error "400" "MissingRequestBodyError" "is empty" "-bucketName" "$bucket_name" "-method" "POST" "-query" "delete" "-contentMD5"
  assert_success
}

# tags: curl, DeleteObjects, malformed-message
@test "REST - DeleteObjects - no objects added to payload" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2109"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_expect_error "400" "MalformedXML" "was not well-formed" "-bucketName" "$bucket_name" "-commandType" "deleteObjects" "-contentMD5"
  assert_success

  run get_object_rest "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/$file_name-copy"
  assert_success
}

# tags: curl, DeleteObjects
@test "REST - DeleteObjects - nonexistent key" {
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  local incorrect_file_name="${file_name}a"
  run send_rest_go_command_callback "200" "check_xml_element_contains" "-bucketName" "$bucket_name" "-commandType" "deleteObjects" \
   "-contentMD5" "-objectsToDelete" "key=$incorrect_file_name" "--" "$incorrect_file_name" "DeleteResult" "Deleted" "Key"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success
}

# tags: curl, DeleteObjects
@test "REST - DeleteObjects - ETag mismatch" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2112"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_callback "200" "check_delete_objects_precondition_error" "-bucketName" "$bucket_name" "-commandType" "deleteObjects" \
   "-contentMD5" "-objectsToDelete" "key=$file_name;eTag=abc" "--" "$file_name"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success
}

# tags: curl, DeleteObjects
@test "REST - DeleteObject - ETag match" {
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run get_etag_rest "$bucket_name" "$file_name"
  assert_success
  etag="$output"

  run send_rest_go_command_callback "200" "check_xml_element_contains" "-bucketName" "$bucket_name" "-commandType" "deleteObjects" \
   "-contentMD5" "-objectsToDelete" "key=$file_name;eTag=$etag" "--" "$file_name" "DeleteResult" "Deleted" "Key"
  assert_success

  run verify_object_not_found "$bucket_name" "$file_name"
  assert_success
}

# tags: curl, DeleteObjects, versioning
@test "REST - DeleteObjects - version ID mismatch" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2119"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  incorrect_version="abc"
  run send_rest_go_command_callback "200" "check_delete_objects_version_error" "-bucketName" "$bucket_name" "-commandType" "deleteObjects" \
   "-contentMD5" "-objectsToDelete" "key=$file_name;versionId=$incorrect_version" "--" "$file_name" "$incorrect_version"
  assert_success

  run download_and_compare_file "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name" "$TEST_FILE_FOLDER/${file_name}-copy"
  assert_success
}

# tags: curl, DeleteObjects, versioning
@test "REST - DeleteObjects - version ID" {
  if [ "$RECREATE_BUCKETS" == "false" ]; then
    skip "cannot change versioning status for static buckets"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_bucket_versioning_rest "$bucket_name" "Enabled"
  assert_success

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_callback "200" "parse_version_id" "-bucketName" "$bucket_name" "-query" "versions" "--" "true"
  assert_success
  version_id="$output"

  run send_rest_go_command_callback "200" "check_xml_element_contains" "-bucketName" "$bucket_name" "-commandType" "deleteObjects" \
   "-contentMD5" "-objectsToDelete" "key=$file_name;versionId=$version_id" "--" "$file_name" "DeleteResult" "Deleted" "Key"
  assert_success

  run verify_object_not_found "$bucket_name" "$file_name"
  assert_success
}

@test "REST - DeleteObjects - quiet mode" {
  if [ "$DIRECT" != "true" ]; then
    skip "https://github.com/versity/versitygw/issues/2124"
  fi
  run setup_bucket_and_file_v3 "$BUCKET_ONE_NAME"
  assert_success
  read -r bucket_name file_name <<< "$output"

  run put_object_rest "$TEST_FILE_FOLDER/$file_name" "$bucket_name" "$file_name"
  assert_success

  run send_rest_go_command_callback "200" "check_for_empty_element" "-bucketName" "$bucket_name" "-commandType" "deleteObjects" \
   "-contentMD5" "-objectsToDelete" "key=${file_name}" "-deleteObjectsQuietMode" "--" "DeleteResult"
  assert_success

  run verify_object_not_found "$bucket_name" "$file_name"
  assert_success
}
