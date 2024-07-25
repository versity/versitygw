#!/usr/bin/env bash

upload_part() {
  if [ $# -ne 5 ]; then
    log 2 "upload multipart part function must have bucket, key, upload ID, file name, part number"
    return 1
  fi
  local etag_json
  record_command "upload-part" "client:s3api"
  if ! etag_json=$(aws --no-verify-ssl s3api upload-part --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --body "$4-$(($5-1))" 2>&1); then
    log 2 "Error uploading part $5: $etag_json"
    return 1
  fi
  if ! etag=$(echo "$etag_json" | grep -v "InsecureRequestWarning" | jq '.ETag' 2>&1); then
    log 2 "error obtaining etag: $etag"
    return 1
  fi
  export etag
}