#!/usr/bin/env bash

upload_and_check_attributes() {
  if [ $# -ne 2 ]; then
    log 2 "'upload_and_check_attributes' requires test file, file size"
    return 1
  fi
  if ! perform_multipart_upload_rest "$BUCKET_ONE_NAME" "$1" "$TEST_FILE_FOLDER/$1-0" "$TEST_FILE_FOLDER/$1-1" \
      "$TEST_FILE_FOLDER/$1-2" "$TEST_FILE_FOLDER/$1-3"; then
    log 2 "error uploading and checking parts"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$1" ATTRIBUTES="ETag,StorageClass,ObjectParts,ObjectSize" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error listing object attributes: $result"
    return 1
  fi
  if ! check_attributes_after_upload "$2"; then
    log 2 "error checking attributes after upload"
    return 1
  fi
}

check_attributes_after_upload() {
  if [ $# -ne 1 ]; then
    log 2 "'check_attributes_after_upload' requires file size"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! object_size=$(xmllint --xpath '//*[local-name()="ObjectSize"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting checksum: $object_size"
    return 1
  fi
  # shellcheck disable=SC2154
  if [ "$object_size" != "$1" ]; then
    log 2 "expected file size of '$file_size', was '$object_size'"
    return 1
  fi
  if ! error=$(xmllint --xpath '//*[local-name()="StorageClass"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting storage class: $error"
    return 1
  fi
  if ! etag=$(xmllint --xpath '//*[local-name()="ETag"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting etag: $etag"
    return 1
  fi
  if ! [[ $etag =~ ^[a-fA-F0-9]{32}-4$ ]]; then
    log 2 "unexpected etag pattern ($etag)"
    return 1
  fi
  if ! parts_count=$(xmllint --xpath '//*[local-name()="PartsCount"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting parts_count: $parts_count"
    return 1
  fi
  if [[ $parts_count != 4 ]]; then
    log 2 "unexpected parts count, expected 4, was $parts_count"
    return 1
  fi
  return 0
}

check_attributes_invalid_param() {
  if [ $# -ne 1 ]; then
    log 2 "'check_attributes_invalid_param' requires test file"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$1" ATTRIBUTES="ETags" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error listing object attributes: $result"
    return 1
  fi
  if [ "$result" != "400" ]; then
    log 2 "expected response code of '400', was '$result'"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! code=$(xmllint --xpath '//*[local-name()="Code"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting code: $code"
    return 1
  fi
  if [ "$code" != "InvalidArgument" ]; then
    log 2 "expected 'InvalidArgument', was '$code'"
    return 1
  fi
}

add_and_check_checksum() {
  if [ $# -ne 2 ]; then
    log 2 "'add_and_check_checksum' requires data file, key"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" DATA_FILE="$1" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$2" CHECKSUM_TYPE="sha256" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/put_object.sh); then
    log 2 "error sending object file: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result' (output: $(cat "$TEST_FILE_FOLDER/result.txt")"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$BUCKET_ONE_NAME" OBJECT_KEY="$2" ATTRIBUTES="Checksum" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error listing object attributes: $result (output: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected response code of '200', was '$result'"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! checksum=$(xmllint --xpath '//*[local-name()="ChecksumSHA256"]/text()' "$TEST_FILE_FOLDER/attributes.txt" 2>&1); then
    log 2 "error getting checksum: $checksum"
    return 1
  fi
  if [ "$checksum" == "" ]; then
    log 2 "empty checksum"
    return 1
  fi
}

get_etag_attribute_rest() {
  if [ $# -ne 3 ]; then
    log 2 "'get_etag_attribute_rest' requires bucket name, object key, expected etag"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" ATTRIBUTES="ETag" OUTPUT_FILE="$TEST_FILE_FOLDER/attributes.txt" ./tests/rest_scripts/get_object_attributes.sh); then
    log 2 "error attempting to get object info: $result"
    return 1
  fi
  log 5 "attributes: $(cat "$TEST_FILE_FOLDER/attributes.txt")"
  if ! check_xml_element "$TEST_FILE_FOLDER/attributes.txt" "$3" "GetObjectAttributesResponse" "ETag"; then
    log 2 "etag mismatch"
    return 1
  fi
  return 0
}