#!/usr/bin/env bash

create_presigned_url() {
  if ! check_param_count_v2 "client, bucket, key" 3 $#; then
    return 1
  fi
  local response presign_result=0 presigned_url

  local presign_result=0
  if [[ $1 == 's3api' ]]; then
    response=$(send_command aws s3 presign "s3://$2/$3" --expires-in 900 2>&1) || presign_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    response=$(send_command s3cmd --no-check-certificate "${S3CMD_OPTS[@]}" signurl "s3://$2/$3" "$(echo "$(date +%s)" + 900 | bc)" 2>&1) || presign_result=$?
  elif [[ $1 == 'mc' ]]; then
    response=$(send_command mc --insecure share download --recursive "$MC_ALIAS/$2/$3" 2>&1) || presign_result=$?
  else
    log 2 "unrecognized client type $1"
    return 1
  fi
  if [[ $presign_result -ne 0 ]]; then
    log 2 "error generating presigned url: $response"
    return 1
  fi
  if [ "$1" == 'mc' ]; then
    presigned_url=$(echo "$response" | grep "Share: " | sed 's/.*Share: //')
    presigned_url="${presigned_url//$'\r'/}"
  else
    presigned_url="$response"
  fi
  echo "$presigned_url"
  return 0
}
