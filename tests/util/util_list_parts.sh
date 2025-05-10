#!/usr/bin/env bash

check_part_list_rest_etags() {
  if ! etags=$(xmllint --xpath '//*[local-name()="ETag"]/text()' "$TEST_FILE_FOLDER/parts.txt" | tr '\n' ' ' 2>&1); then
    log 2 "error retrieving etags: $etags"
    return 1
  fi
  read -ra etags_array <<< "$etags"
  idx=0
  if [ $# -ne ${#etags_array[@]} ]; then
    log 2 "expected tag size of '$#', actual ${#etags_array[@]}"
    return 1
  fi
  while [ $# -gt 0 ]; do
    if [ "$1" != "${etags_array[$idx]}" ]; then
      log 2 "etag mismatch (expected '$1', actual ${etags_array[$idx]})"
      return 1
    fi
    ((idx++))
    shift
  done
  return 0
}

check_part_list_rest() {
  if [ $# -lt 4 ]; then
    log 2 "'check_part_list_rest' requires bucket, file name, upload ID, expected count, etags"
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$3" OUTPUT_FILE="$TEST_FILE_FOLDER/parts.txt" ./tests/rest_scripts/list_parts.sh); then
    log 2 "error listing multipart upload parts: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "list-parts returned response code: $result, reply:  $(cat "$TEST_FILE_FOLDER/parts.txt")"
    return 1
  fi
  log 5 "parts list: $(cat "$TEST_FILE_FOLDER/parts.txt")"
  if ! parts_upload_id=$(xmllint --xpath '//*[local-name()="UploadId"]/text()' "$TEST_FILE_FOLDER/parts.txt" 2>&1); then
    log 2 "error retrieving UploadId: $parts_upload_id"
    return 1
  fi
  if [ "$parts_upload_id" != "$3" ]; then
    log 2 "expected '$3', UploadId value is '$parts_upload_id'"
    return 1
  fi
  if ! part_count=$(xmllint --xpath 'count(//*[local-name()="Part"])' "$TEST_FILE_FOLDER/parts.txt" 2>&1); then
    log 2 "error retrieving part count: $part_count"
    return 1
  fi
  if [ "$part_count" != "$4" ]; then
    log 2 "expected $4, 'Part' count is '$part_count'"
    return 1
  fi
  if [ "$4" == 0 ]; then
    return 0
  fi
  if ! check_part_list_rest_etags "${@:5}"; then
    log 2 "error checking etags"
    return 1
  fi
  return 0
}

perform_multipart_upload_rest() {
  if [ $# -ne 6 ]; then
    log 2 "'upload_check_parts' requires bucket, key, part list"
    return 1
  fi
  if ! upload_id=$(create_multipart_upload_rest "$1" "$2" 2>&1); then
    log 2 "error creating multipart upload"
    return 1
  fi
  # shellcheck disable=SC2154
  if ! etag=$(upload_part_rest "$1" "$2" "$upload_id" 1 "$3" 2>&1); then
    log 2 "error uploading part 1"
    return 1
  fi
  # shellcheck disable=SC2154
  parts_payload="<Part><ETag>$etag</ETag><PartNumber>1</PartNumber></Part>"
  if ! etag=$(upload_part_rest "$1" "$2" "$upload_id" 2 "$4" 2>&1); then
    log 2 "error uploading part 2: $etag"
    return 1
  fi
  parts_payload+="<Part><ETag>$etag</ETag><PartNumber>2</PartNumber></Part>"
  if ! etag=$(upload_part_rest "$1" "$2" "$upload_id" 3 "$5" 2>&1); then
    log 2 "error uploading part 3: $etag"
    return 1
  fi
  parts_payload+="<Part><ETag>$etag</ETag><PartNumber>3</PartNumber></Part>"
  if ! etag=$(upload_part_rest "$1" "$2" "$upload_id" 4 "$6" 2>&1); then
    log 2 "error uploading part 4: $etag"
    return 1
  fi
  parts_payload+="<Part><ETag>$etag</ETag><PartNumber>4</PartNumber></Part>"
  if ! complete_multipart_upload_rest "$1" "$2" "$3" "$4"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

upload_check_parts() {
  if [ $# -ne 6 ]; then
    log 2 "'upload_check_parts' requires bucket, key, part list"
    return 1
  fi
  if ! upload_id=$(create_multipart_upload_rest "$1" "$2" 2>&1); then
    log 2 "error creating upload"
    return 1
  fi
  # shellcheck disable=SC2154
  if ! check_part_list_rest "$1" "$2" "$upload_id" 0; then
    log 2 "error checking part list before part upload"
    return 1
  fi
  sleep 5
  parts_payload=""
  if ! upload_check_part "$1" "$2" "$upload_id" 1 "$3"; then
    log 2 "error uploading and checking first part"
    return 1
  fi
  if ! list_multipart_uploads_rest "$1"; then
    log 2 "error listing uploads"
    return 1
  fi
  etag_one=$etag
  if ! upload_check_part "$1" "$2" "$upload_id" 2 "$4" "$etag_one"; then
    log 2 "error uploading and checking second part"
    return 1
  fi
  etag_two=$etag
  if ! upload_check_part "$1" "$2" "$upload_id" 3 "$5" "$etag_one" "$etag_two"; then
    log 2 "error uploading and checking third part"
    return 1
  fi
  etag_three=$etag
  if ! upload_check_part "$1" "$2" "$upload_id" 4 "$6" "$etag_one" "$etag_two" "$etag_three"; then
    log 2 "error uploading and checking fourth part"
    return 1
  fi
  log 5 "PARTS PAYLOAD:  $parts_payload"
  if ! complete_multipart_upload_rest "$1" "$2" "$upload_id" "$parts_payload"; then
    log 2 "error completing multipart upload"
    return 1
  fi
  return 0
}

upload_check_part() {
  if [ $# -lt 5 ]; then
    log 2 "'upload_check_part' requires bucket, key, upload ID, part number, part, etags"
    return 1
  fi
  if ! etag=$(upload_part_rest "$1" "$2" "$3" "$4" "$5" 2>&1); then
    log 2 "error uploading part $4: $etag"
    return 1
  fi
  parts_payload+="<Part><ETag>$etag</ETag><PartNumber>$4</PartNumber></Part>"
  # shellcheck disable=SC2068
  if ! check_part_list_rest "$1" "$2" "$3" "$4" "${@:6}" "$etag"; then
    log 2 "error checking part list after upload $4"
    return 1
  fi
}
