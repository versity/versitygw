#!/usr/bin/env bash

block_delete_object_without_permission() {
  if [ $# -ne 4 ]; then
    log 2 "'attempt_delete_object_without_permission' requires bucket, file, username, password"
    return 1
  fi
  if delete_object_with_user "s3api" "$1" "$2" "$3" "$4"; then
    log 2 "able to delete object despite lack of permissions"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$delete_object_error" != *"AccessDenied"* ]]; then
    log 2 "invalid delete object error: $delete_object_error"
    return 1
  fi
  return 0
}

delete_object_empty_bucket_check_error() {
  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="" ./tests/rest_scripts/delete_objects.sh); then
    log 2 "error deleting objects: $result"
    return 1
  fi
  log 5 "result: $(cat "$TEST_FILE_FOLDER/result.txt")"
  if ! error=$(xmllint --xpath "Error" "$TEST_FILE_FOLDER/result.txt" 2>&1); then
    log 2 "error getting XML error data: $error"
    return 1
  fi
  echo -n "$error" > "$TEST_FILE_FOLDER/error.txt"
  if ! check_xml_element "$TEST_FILE_FOLDER/error.txt" "MethodNotAllowed" "Code"; then
    log 2 "Code mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/error.txt" "POST" "Method"; then
    log 2 "Method mismatch"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/error.txt" "SERVICE" "ResourceType"; then
    log 2 "ResourceType mismatch"
    return 1
  fi
  return 0
}

delete_objects_no_content_md5_header() {
  if [ $# -ne 1 ]; then
    log 2 "delete_objects_no_content_md5_header requires bucket name"
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

  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" PAYLOAD="$data" BUCKET_NAME="$1" HAS_CONTENT_MD5="false" ./tests/rest_scripts/delete_objects.sh); then
    log 2 "error deleting objects: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected response code '400', actual '$result' ($(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  if ! check_xml_element "$TEST_FILE_FOLDER/result.txt" "InvalidRequest" "Error" "Code"; then
    log 2 "error checking error element"
    return 1
  fi
}

delete_objects_verify_success() {
  if [ $# -ne 3 ]; then
    log 2 "'delete_objects_verify_success' requires bucket name, two objects"
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

  if ! result=$(OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" COMMAND_LOG="$COMMAND_LOG" PAYLOAD="$data" BUCKET_NAME="$1" ./tests/rest_scripts/delete_objects.sh); then
    log 2 "error deleting objects: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result ($(cat "$TEST_FILE_FOLDER/result.txt"))"
    return 1
  fi
  return 0
}
