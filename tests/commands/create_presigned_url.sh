#!/usr/bin/env bash

create_presigned_url() {
  if [[ $# -ne 3 ]]; then
    log 2 "create presigned url function requires command type, bucket, and filename"
    return 1
  fi

  local presign_result=0
  if [[ $1 == 's3api' ]]; then
    presigned_url=$(send_command aws s3 presign "s3://$2/$3" --expires-in 900) || presign_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    presigned_url=$(send_command s3cmd --no-check-certificate "${S3CMD_OPTS[@]}" signurl "s3://$2/$3" "$(echo "$(date +%s)" + 900 | bc)") || presign_result=$?
  elif [[ $1 == 'mc' ]]; then
    presigned_url_data=$(send_command mc --insecure share download --recursive "$MC_ALIAS/$2/$3") || presign_result=$?
    presigned_url="${presigned_url_data#*Share: }"
  else
    log 2 "unrecognized command type $1"
    return 1
  fi
  if [[ $presign_result -ne 0 ]]; then
    log 2 "error generating presigned url: $presigned_url"
    return 1
  fi
  export presigned_url
  return 0
}
