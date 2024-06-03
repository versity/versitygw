#!/usr/bin/env bash

upload_part_copy() {
  if [ $# -ne 5 ]; then
    echo "upload multipart part copy function must have bucket, key, upload ID, file name, part number"
    return 1
  fi
  local etag_json
  echo "$1 $2 $3 $4 $5"
  etag_json=$(aws --no-verify-ssl s3api upload-part-copy --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --copy-source "$1/$4-$(($5-1))") || local uploaded=$?
  if [[ $uploaded -ne 0 ]]; then
    echo "Error uploading part $5: $etag_json"
    return 1
  fi
  etag=$(echo "$etag_json" | jq '.CopyPartResult.ETag')
  export etag
}

upload_part_copy_with_range() {
  if [ $# -ne 6 ]; then
    log 2 "upload multipart part copy function must have bucket, key, upload ID, file name, part number, range"
    return 1
  fi
  local etag_json
  log 5 "bucket: $1, key: $2, upload ID: $3, file name: $4, range: $5"
  etag_json=$(aws --no-verify-ssl s3api upload-part-copy --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --copy-source "$1/$4-$(($5-1))" --copy-source-range "$6" 2>&1) || local uploaded=$?
  if [[ $uploaded -ne 0 ]]; then
    log 2 "Error uploading part $5: $etag_json"
    export upload_part_copy_error=$etag_json
    return 1
  fi
  etag=$(echo "$etag_json" | grep -v "InsecureRequestWarning" | jq '.CopyPartResult.ETag')
  export etag
}