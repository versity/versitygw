#!/usr/bin/env bash

# initialize a multipart upload
# params:  bucket, key
# return 0 for success, 1 for failure
create_multipart_upload() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -ne 2 ]; then
    log 2 "create multipart upload function must have bucket, key"
    return 1
  fi

  if ! multipart_data=$(aws --no-verify-ssl s3api create-multipart-upload --bucket "$1" --key "$2" 2>&1); then
    log 2 "Error creating multipart upload: $multipart_data"
    return 1
  fi

  if ! upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq -r '.UploadId' 2>&1); then
    log 2 "error parsing upload ID: $upload_id"
    return 1
  fi
  upload_id="${upload_id//\"/}"
  export upload_id
  return 0
}

create_multipart_upload_with_user() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -ne 4 ]; then
    log 2 "create multipart upload function must have bucket, key, username, password"
    return 1
  fi

  if ! multipart_data=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" aws --no-verify-ssl s3api create-multipart-upload --bucket "$1" --key "$2" 2>&1); then
    log 2 "Error creating multipart upload: $multipart_data"
    return 1
  fi

  if ! upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq -r '.UploadId' 2>&1); then
    log 2 "error parsing upload ID: $upload_id"
    return 1
  fi
  upload_id="${upload_id//\"/}"
  export upload_id
  return 0
}

create_multipart_upload_params() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -ne 8 ]; then
    log 2 "create multipart upload function with params must have bucket, key, content type, metadata, object lock legal hold status, " \
      "object lock mode, object lock retain until date, and tagging"
    return 1
  fi
  local multipart_data
  multipart_data=$(aws --no-verify-ssl s3api create-multipart-upload \
    --bucket "$1" \
    --key "$2" \
    --content-type "$3" \
    --metadata "$4" \
    --object-lock-legal-hold-status "$5" \
    --object-lock-mode "$6" \
    --object-lock-retain-until-date "$7" \
    --tagging "$8" 2>&1) || local create_result=$?
  if [[ $create_result -ne 0 ]]; then
    log 2 "error creating multipart upload with params: $multipart_data"
    return 1
  fi
  export multipart_data
  upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq '.UploadId')
  upload_id="${upload_id//\"/}"
  export upload_id
  return 0
}

create_multipart_upload_custom() {
  record_command "create-multipart-upload" "client:s3api"
  if [ $# -lt 2 ]; then
    log 2 "create multipart upload custom function must have at least bucket and key"
    return 1
  fi
  local multipart_data
  log 5 "additional create multipart params"
  for i in "$@"; do
    log 5 "$i"
  done
  log 5 "${*:3}"
  log 5 "aws --no-verify-ssl s3api create-multipart-upload --bucket $1 --key $2 ${*:3}"
  multipart_data=$(aws --no-verify-ssl s3api create-multipart-upload --bucket "$1" --key "$2" 2>&1) || local result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error creating custom multipart data command: $multipart_data"
    return 1
  fi
  export multipart_data
  log 5 "multipart data: $multipart_data"
  upload_id=$(echo "$multipart_data" | grep -v "InsecureRequestWarning" | jq '.UploadId')
  upload_id="${upload_id//\"/}"
  log 5 "upload id: $upload_id"
  export upload_id
  return 0
}
