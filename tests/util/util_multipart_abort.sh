#!/usr/bin/env bash

check_abort_access_denied() {
  if [ $# -ne 5 ]; then
    log 2 "'check_abort_access_denied' requires bucket, file, username, password"
    return 1
  fi
  if abort_multipart_upload_with_user "$1" "$2" "$3" "$4" "$5"; then
    log 2 "abort multipart upload succeeded despite lack of permissions"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$abort_multipart_upload_error" != *"AccessDenied"* ]]; then
    log 2 "unexpected abort error:  $abort_multipart_upload_error"
    return 1
  fi
  return 0
}

create_abort_multipart_upload_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'create_abort_upload_rest' requires bucket, key"
    return 1
  fi
  if ! list_and_check_upload "$1" "$2"; then
    log 2 "error listing multipart uploads before creation"
    return 1
  fi
  log 5 "uploads before upload: $(cat "$TEST_FILE_FOLDER/uploads.txt")"
  if ! create_upload_and_get_id_rest "$1" "$2"; then
    log 2 "error creating upload"
    return 1
  fi
  if ! list_and_check_upload "$1" "$2" "$upload_id"; then
    log 2 "error listing multipart uploads after upload creation"
    return 1
  fi
  log 5 "uploads after upload creation: $(cat "$TEST_FILE_FOLDER/uploads.txt")"
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" OBJECT_KEY="$2" UPLOAD_ID="$upload_id" OUTPUT_FILE="$TEST_FILE_FOLDER/result.txt" ./tests/rest_scripts/abort_multipart_upload.sh); then
    log 2 "error aborting multipart upload: $result"
    return 1
  fi
  if [ "$result" != "204" ]; then
    log 2 "expected '204' response, actual was '$result' (error: $(cat "$TEST_FILE_FOLDER"/result.txt)"
    return 1
  fi
  log 5 "final uploads: $(cat "$TEST_FILE_FOLDER/uploads.txt")"
  if ! list_and_check_upload "$1" "$2"; then
    log 2 "error listing multipart uploads after abort"
    return 1
  fi
  return 0
}

# param: bucket name
# return 0 for success, 1 for error
abort_all_multipart_uploads() {
  if [ $# -ne 1 ]; then
    log 2 "'abort_all_multipart_uploads' requires bucket name"
    return 1
  fi
  if ! list_multipart_uploads "$1"; then
    log 2 "error listing multipart uploads"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "UPLOADS: $uploads"
  if ! upload_set=$(echo "$uploads" | grep -v "InsecureRequestWarning" | jq -c '.Uploads[]' 2>&1); then
    if [[ $upload_set == *"Cannot iterate over null"* ]]; then
      return 0
    else
      log 2 "error getting upload set: $upload_set"
      return 1
    fi
  fi
  log 5 "UPLOAD SET: $upload_set"
  for upload in $upload_set; do
    log 5 "UPLOAD: $upload"
    if ! upload_id=$(echo "$upload" | jq -r ".UploadId" 2>&1); then
      log 2 "error getting upload ID: $upload_id"
      return 1
    fi
    log 5 "upload ID: $upload_id"
    if ! key=$(echo "$upload" | jq -r ".Key" 2>&1); then
      log 2 "error getting key: $key"
      return 1
    fi
    log 5 "Aborting multipart upload for key: $key, UploadId: $upload_id"
    if ! abort_multipart_upload "$1" "$key" "$upload_id"; then
      log 2 "error aborting multipart upload"
      return 1
    fi
  done
}

# run upload, then abort it
# params:  bucket, key, local file location, number of parts to split into before uploading
# return 0 for success, 1 for failure
run_then_abort_multipart_upload() {
  if [ $# -ne 4 ]; then
    log 2 "run then abort multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  if ! multipart_upload_before_completion "$1" "$2" "$3" "$4"; then
    log 2 "error performing pre-completion multipart upload"
    return 1
  fi

  if ! abort_multipart_upload "$1" "$2" "$upload_id"; then
    log 2 "error aborting multipart upload"
    return 1
  fi
  return 0
}
