#!/usr/bin/env bash

abort_all_multipart_uploads() {
  if [[ $# -ne 1 ]]; then
    echo "abort all multipart uploads command missing bucket name"
    return 1
  fi

  upload_list=$(aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1" 2>&1) || list_result=$?
  if [[ $list_result -ne 0 ]]; then
    echo "error listing multipart uploads: $upload_list"
    return 1
  fi
  log 5 "$upload_list"
  while IFS= read -r line; do
    if [[ $line != *"InsecureRequestWarning"* ]]; then
      modified_upload_list+=("$line")
    fi
  done <<< "$upload_list"

  log 5 "Modified upload list: ${modified_upload_list[*]}"
  has_uploads=$(echo "${modified_upload_list[*]}" | jq 'has("Uploads")')
  if [[ $has_uploads != false ]]; then
    lines=$(echo "${modified_upload_list[*]}" | jq -r '.Uploads[] | "--key \(.Key) --upload-id \(.UploadId)"') || lines_result=$?
    if [[ $lines_result -ne 0 ]]; then
      echo "error getting lines for multipart upload delete: $lines"
      return 1
    fi

    log 5 "$lines"
    while read -r line; do
      # shellcheck disable=SC2086
      error=$(aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" $line 2>&1) || abort_result=$?
      if [[ $abort_result -ne 0 ]]; then
        echo "error aborting multipart upload: $error"
        return 1
      fi
    done <<< "$lines"
  fi
  return 0
}