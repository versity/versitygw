#!/usr/bin/env bash

get_bucket_location() {
  if [[ $# -ne 2 ]]; then
    echo "get bucket location command requires command type, bucket name"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    get_bucket_location_aws "$2" || get_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_bucket_location_s3cmd "$2" || get_result=$?
  elif [[ $1 == 'mc' ]]; then
    get_bucket_location_mc "$2" || get_result=$?
  else
    echo "command type '$1' not implemented for get_bucket_location"
    return 1
  fi
  if [[ $get_result -ne 0 ]]; then
    return 1
  fi
  location=$(echo "$location_json" | jq -r '.LocationConstraint')
  export location
}

get_bucket_location_aws() {
  if [[ $# -ne 1 ]]; then
    echo "get bucket location (aws) requires bucket name"
    return 1
  fi
  location_json=$(aws --no-verify-ssl s3api get-bucket-location --bucket "$1") || location_result=$?
  if [[ $location_result -ne 0 ]]; then
    echo "error getting bucket location: $location"
    return 1
  fi
  bucket_location=$(echo "$location_json" | jq -r '.LocationConstraint')
  export bucket_location
  return 0
}

get_bucket_location_s3cmd() {
  if [[ $# -ne 1 ]]; then
    echo "get bucket location (s3cmd) requires bucket name"
    return 1
  fi
  info=$(s3cmd --no-check-certificate info "s3://$1") || results=$?
  if [[ $results -ne 0 ]]; then
    echo "error getting s3cmd info: $info"
    return 1
  fi
  bucket_location=$(echo "$info" | grep -o 'Location:.*' | awk '{print $2}')
  export bucket_location
  return 0
}

get_bucket_location_mc() {
  if [[ $# -ne 1 ]]; then
    echo "get bucket location (mc) requires bucket name"
    return 1
  fi
  info=$(mc --insecure stat "$MC_ALIAS/$1") || results=$?
  if [[ $results -ne 0 ]]; then
    echo "error getting s3cmd info: $info"
    return 1
  fi
  bucket_location=$(echo "$info" | grep -o 'Location:.*' | awk '{print $2}')
  export bucket_location
  return 0
}