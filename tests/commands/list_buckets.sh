#!/usr/bin/env bash

list_buckets() {
  if [ $# -ne 1 ]; then
    echo "list buckets command missing command type"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    buckets=$(aws --no-verify-ssl s3 ls 2>&1 s3://) || exit_code=$?
  elif [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    list_buckets_s3api || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    buckets=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3:// 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    buckets=$(mc --insecure ls "$MC_ALIAS" 2>&1) || exit_code=$?
  else
    echo "list buckets command not implemented for '$1'"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error listing buckets: $buckets"
    return 1
  fi

  if [[ $1 == 's3api' ]] || [[ $1 == 'aws' ]]; then
    return 0
  fi

  bucket_array=()
  while IFS= read -r line; do
    bucket_name=$(echo "$line" | awk '{print $NF}')
    bucket_array+=("${bucket_name%/}")
  done <<< "$buckets"
  export bucket_array
  return 0
}

list_buckets_s3api() {
  output=$(aws --no-verify-ssl s3api list-buckets 2>&1) || exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    echo "error listing buckets: $output"
    return 1
  fi

  modified_output=""
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      modified_output+="$line"
    fi
  done <<< "$output"

  bucket_array=()
  names=$(jq -r '.Buckets[].Name' <<<"$modified_output")
  IFS=$'\n' read -rd '' -a bucket_array <<<"$names"

  export bucket_array
  return 0
}