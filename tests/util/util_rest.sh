#!/usr/bin/env bash

parse_bucket_list() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "bucket list: $(cat "$1")"
  bucket_list=$(xmllint --xpath '//*[local-name()="Bucket"]/*[local-name()="Name"]/text()' "$1")
  bucket_array=()
  while read -r bucket; do
    bucket_array+=("$bucket")
  done <<< "$bucket_list"
  log 5 "bucket array: ${bucket_array[*]}"
}

parse_object_list() {
  # shellcheck disable=SC2154
  object_list=$(echo "$reply" | xmllint --xpath '//*[local-name()="Bucket"]/*[local-name()="Name"]/text()' -)
  object_array=()
  while read -r object; do
    object_array+=("$object")
  done <<< "$object_list"
  log 5 "object array: ${object_array[*]}"
}

get_signature() {
  date_key=$(echo -n "$ymd" | openssl dgst -sha256 -mac HMAC -macopt key:"AWS4${AWS_SECRET_ACCESS_KEY}" | awk '{print $2}')
  date_region_key=$(echo -n "$AWS_REGION" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_key" | awk '{print $2}')
  date_region_service_key=$(echo -n "s3" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_region_key" | awk '{print $2}')
  signing_key=$(echo -n "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_region_service_key" | awk '{print $2}')
  # shellcheck disable=SC2034
  signature=$(echo -n "$sts_data" | openssl dgst -sha256 \
                 -mac HMAC \
                 -macopt hexkey:"$signing_key" | awk '{print $2}')
}

hmac_sha256() {
  key="$1"
  data="$2"
  #echo "key: $1"
  echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt "$key" | sed 's/^.* //'
}

send_rest_command_no_payload_no_bucket() {
  generate_hash_for_payload ""
  get_creq_string
}

send_rest_command_no_payload() {
  if [ $# -ne 1 ]; then
    log 2 "'send_rest_command_no_payload' requires payload"
    return 1
  fi
}

generate_hash_for_payload() {
  if [ $# -ne 1 ]; then
    log 2 "'generate_hash_for_payload' requires payload string"
    return 1
  fi
  payload_hash="$(echo -n "$1" | sha256sum | awk '{print $1}')"
}

generate_hash_for_payload_file() {
  if [ $# -ne 1 ]; then
    log 2 "'generate_hash_for_payload' requires filename"
    return 1
  fi
  payload_hash="$(sha256sum "$1" | awk '{print $1}')"
}

get_creq_string_list_buckets() {
  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
    canonical_request="GET
/

host:${AWS_ENDPOINT_URL#*//}
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
$payload_hash"
}

generate_creq_file() {
  if [ $# -ne 3 ]; then
    log 2 "'generate_creq_file' command requires bucket name, creq file name, hash"
    return 1
  fi
  current_time=$(date -u +"%Y%m%dT%H%M%SZ")
cat <<EOF > "$2"
GET
/

host:$1.s3.amazonaws.com
x-amz-content-sha256:$3
x-amz-date:$current_time

host;x-amz-content-sha256;x-amz-date
$3
EOF

  canonical_request="GET
/

host:$1.s3.amazonaws.com
x-amz-content-sha256:$3
x-amz-date:$current_time

host;x-amz-content-sha256;x-amz-date
$3"
  log 5 "canonical: $canonical_request"

  log 5 "TEST CREQ"
  log 5 "$(cat test.creq)"
}

generate_sts_string() {
  if [ $# -ne 2 ]; then
    log 2 "'generate_sts_string' requires current date and time, canonical request string"
    return 1
  fi

  ymd=$(echo "$1" | cut -c1-8)
  creq_hash="$(echo -n "$2" | openssl dgst -sha256 | awk '{print $2}')"
  sts_data="AWS4-HMAC-SHA256
$1
$ymd/$AWS_REGION/s3/aws4_request
$creq_hash"

  return 0
}

generate_sts_file() {
  if [ $# -ne 3 ]; then
    log 2 "'generate_sts_file' requires date, hash, file name"
    return 1
  fi
  ymd=$(echo "$current_time" | cut -c1-8)
  creq_hash="$(echo -n "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')"
  echo "creq hash: $creq_hash"
cat <<EOF > "$3"
AWS4-HMAC-SHA256
$1
$ymd/us-west-2/s3/aws4_request
$creq_hash
EOF
  sts_data="AWS4-HMAC-SHA256
$1
$ymd/us-west-2/s3/aws4_request
$creq_hash"

  log 5 "TEST STS"
  log 5 "$(cat test.sts)"
}
