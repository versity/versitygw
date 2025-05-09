#!/usr/bin/env bash

# Copyright 2024 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

source ./tests/rest_scripts/rest.sh
source ./tests/util/util_file.sh

# Fields

load_parameters() {
  test_mode=${TEST_MODE:=true}
  # shellcheck disable=SC2034
  command_file="${COMMAND_FILE:=command.txt}"

  readonly signature_no_data="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  if [ "$test_mode" == "true" ]; then
    current_date_time="20130524T000000Z"
    year_month_day="20130524"
    bucket_name="examplebucket"
    key="chunkObject.txt"
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE"
    # shellcheck disable=SC2034
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    aws_region="us-east-1"
    host="s3.amazonaws.com"
    dd if=/dev/zero bs=1 count=66560 | tr '\0' 'a' > "as.txt"
    data_file="as.txt"
    chunk_size=65536
    trailer="x-amz-checksum-crc32c"
  else
    current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
    year_month_day=$(echo "$current_date_time" | cut -c1-8)
    # shellcheck disable=SC2153
    bucket_name="$BUCKET_NAME"
    key="$OBJECT_KEY"
    # shellcheck disable=SC2153
    data_file="$DATA_FILE"
    chunk_size="${CHUNK_SIZE:=65536}"
    # shellcheck disable=SC2153
    final_signature="$FINAL_SIGNATURE"
    # shellcheck disable=SC2153
    trailer="$TRAILER"
    # shellcheck disable=SC2153
    checksum="$CHECKSUM"
    # shellcheck disable=SC2153
    invalid_checksum_type="${INVALID_CHECKSUM_TYPE:=false}"
  fi

  readonly initial_sts_data="AWS4-HMAC-SHA256-PAYLOAD
$current_date_time
$year_month_day/$aws_region/s3/aws4_request"

  readonly trailer_sts_data="AWS4-HMAC-SHA256-TRAILER
$current_date_time
$year_month_day/$aws_region/s3/aws4_request"

  if [ "$test_mode" == "true" ]; then
    declare_test_expected_vals
  fi
}

declare_test_expected_vals() {
  readonly expected_sts_data="AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
44d48b8c2f70eae815a0198cc73d7a546a73a93359c070abbaa5e6c7de112559"

  readonly expected_sts_chunk_one="AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a"

  readonly expected_sts_chunk_two="AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a"

  readonly expected_sts_chunk_three="AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  readonly expected_sts_chunk_final="AWS4-HMAC-SHA256-TRAILER
20130524T000000Z
20130524/us-east-1/s3/aws4_request
2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992
1e376db7e1a34a8ef1c4bcee131a2d60a1cb62503747488624e10995f448d774"

  readonly expected_canonical_request="PUT
/examplebucket/chunkObject.txt

content-encoding:aws-chunked
host:s3.amazonaws.com
x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
x-amz-date:20130524T000000Z
x-amz-decoded-content-length:66560
x-amz-storage-class:REDUCED_REDUNDANCY
x-amz-trailer:x-amz-checksum-crc32c

content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer
STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"

  readonly expected_command="PUT /examplebucket/chunkObject.txt HTTP/1.1\r
Host: s3.amazonaws.com\r
x-amz-date: 20130524T000000Z\r
x-amz-storage-class: REDUCED_REDUNDANCY\r
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer,Signature=106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e\r
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\r
Content-Encoding: aws-chunked\r
x-amz-decoded-content-length: 66560\r
x-amz-trailer: x-amz-checksum-crc32c\r
Content-Length: 66946\r
\r\n"
}

get_file_size_and_content_length() {
  if ! file_size=$(get_file_size "$data_file"); then
    log_rest 2 "error getting file size: $file_size"
    return 1
  fi
  if [ "$test_mode" == "true" ] && [ "$file_size" != 66560 ]; then
    log_rest 2 "file size mismatch ($file_size)"
    return 1
  fi

  get_chunk_sizes
  log_rest 5 "signature string length: ${#signature_string}"
  content_length=$((length+file_size+${#signature_string}+92))
  if [ "$test_mode" == "true" ] && [ "$content_length" != 66946 ]; then
    log_rest 2 "content length mismatch ($content_length)"
    return 1
  fi
}

calculate_checksum() {
  checksum_type="${trailer/x-amz-checksum-/}"
  log_rest 5 "checksum type: $checksum_type"
  if [ "$CHECKSUM" == "" ] && [ "$invalid_checksum_type" != "true" ]; then
    if ! checksum=$(DATA_FILE="$data_file" CHECKSUM_TYPE="$checksum_type" ./tests/rest_scripts/calculate_checksum.sh 2>&1); then
      log_rest 2 "error getting checksum: $checksum"
      return 1
    fi
  else
    checksum="$CHECKSUM"
  fi
  signature_string="$trailer:$checksum"
  trailer_payload_hash="$(echo "$signature_string" | sha256sum | awk '{print $1}')"
  return 0
}

get_chunk_sizes() {
  chunk_sizes=()
  for ((remaining=file_size; 0<remaining; remaining-=chunk_size)); do
    if ((chunk_size<=remaining)); then
      next_chunk_size=$chunk_size
    else
      next_chunk_size=$remaining
    fi
    chunk_sizes+=("$next_chunk_size")
  done
  chunk_sizes+=("0")
  for size in "${chunk_sizes[@]}"; do
    hex_size=$(printf "%x\n" "$size")
    length=$((length+${#hex_size}+85))
  done
}

get_first_signature() {
  if [ -n "$FIRST_SIGNATURE" ]; then
    first_signature="$FIRST_SIGNATURE"
    return 0
  fi

  canonical_request="PUT
/$bucket_name/$key

content-encoding:aws-chunked
host:$host
x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
x-amz-date:$current_date_time
x-amz-decoded-content-length:$file_size
x-amz-storage-class:REDUCED_REDUNDANCY
x-amz-trailer:$trailer

content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer
STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"

  if [ "$test_mode" == "true" ]; then
    if [ "$expected_canonical_request" != "$canonical_request" ]; then
      log_rest 2 "canonical request mismatch ($canonical_request)"
      exit 1
    fi
  fi

  # shellcheck disable=SC2119
  create_canonical_hash_sts_and_signature
  # shellcheck disable=SC2154
  first_signature="$signature"

  if [ "$test_mode" == "true" ]; then
    # shellcheck disable=SC2154
    if [ "$sts_data" != "$expected_sts_data" ]; then
      log_rest 2 "first STS data mismatch ($sts_data)"
      return 1
    fi
    if [ "$first_signature" != "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e" ]; then
      log_rest 2 "Mismatched first signature ($first_signature)"
      return 1
    fi
  fi
}

create_chunk() {
  if [ $# -ne 4 ]; then
    log_rest 2 "'generate_chunk_signature' requires previous signature, file, offset, bytes"
    return 1
  fi
  chunk_sts_data="$initial_sts_data
$1
$signature_no_data
"
  if [ "$4" -ne 0 ]; then
    if ! error=$(dd if="$2" of="$2.tmp" bs=1 skip="$3" count="$4" 2>&1); then
      log_rest 2 "error retrieving data: $error"
      return 1
    fi
    payload_hash="$(sha256sum "$2.tmp" | awk '{print $1}')"
  else
    payload_hash="$signature_no_data"
  fi
  chunk_sts_data+="$payload_hash"
  create_canonical_hash_sts_and_signature "$chunk_sts_data"
  if [ -n "$final_signature" ] && [ $((idx+1)) -eq ${#chunk_sizes[@]} ]; then
    signature="$final_signature"
  fi
  chunk="$(printf "%x" "$4");chunk-signature=$signature"
  echo -e "$chunk\r" >> "$COMMAND_FILE"
  if [ "$4" -gt 0 ]; then
    dd if="$2.tmp" bs="$4" count=1 >> "$COMMAND_FILE"
    echo -e "\r" >> "$COMMAND_FILE"
  fi
  return 0
}

build_chunks() {
  if [ $# -ne 1 ]; then
    log_rest 2 "'build_chunks' requires first signature"
    return 1
  fi

  last_signature="$1"
  idx=0
  offset=0
  log_rest 5 "chunk sizes: ${chunk_sizes[*]}"
  for chunk_size in "${chunk_sizes[@]}"; do
    if ! build_chunk; then
      log_rest 2 "error building chunk"
      return 1
    fi
    if [ "$test_mode" == "true" ]; then
      if ! check_chunks_and_signatures_in_test_mode $idx; then
        log_rest 2 "error checking test mode signatures"
        return 1
      fi
    fi
    ((idx++))
  done
  return 0
}

build_chunk() {
  if [ "$chunk_size" == 0 ]; then
    if ! create_chunk "$last_signature" "$data_file" 0 0; then
      log_rest 2 "error creating chunk $idx"
      return 1
    fi
  else
    if ! create_chunk "$last_signature" "$data_file" "$offset" "${chunk_sizes[$idx]}"; then
      log_rest 2 "error creating chunk $idx"
      return 1
    fi
    offset=$((offset+chunk_size))
    last_signature="$signature"
  fi
}

build_trailer() {
  log_rest 5 "payload hash: $payload_hash"
  final_sts_data="$trailer_sts_data
$signature
$trailer_payload_hash"
  log_rest 5 "$final_sts_data"
  create_canonical_hash_sts_and_signature "$final_sts_data"
  log_rest 5 "final signature: $signature"
  final_chunk="$signature_string\r
x-amz-trailer-signature:$signature\r
"
  echo -en "$final_chunk" >> "$COMMAND_FILE"
}

check_chunks_and_signatures_in_test_mode() {
  if [ $# -ne 1 ]; then
    log_rest 2 "'check_chunks_and_signatures_in_test_mode' requires chunk number"
    return 1
  fi
  case "$1" in
    0)
      if [ "$chunk_sts_data" != "$expected_sts_chunk_one" ]; then
        log_rest 2 "first chunk STS mismatch ($chunk_sts_data)"
        return 1
      fi
      if [ "$signature" != "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2" ]; then
        log_rest 2 "first chunk signature mismatch ($signature)"
        return 1
      fi
      ;;
    1)
      if [ "$chunk_sts_data" != "$expected_sts_chunk_two" ]; then
        log_rest 2 "second chunk STS mismatch ($chunk_sts_data)"
        return 1
      fi
      if [ "$signature" != "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7" ]; then
        log_rest 2 "second chunk signature mismatch ($signature)"
        return 1
      fi
      ;;
    2)
      if [ "$chunk_sts_data" != "$expected_sts_chunk_three" ]; then
        log_rest 2 "third chunk STS mismatch ($chunk_sts_data)"
        return 1
      fi
      if [ "$signature" != "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992" ]; then
        log_rest 2 "third chunk signature mismatch ($signature)"
        return 1
      fi
      ;;
  esac
}

check_final_signature() {
  if [ "$final_sts_data" != "$expected_sts_chunk_final" ]; then
    log_rest 2 "final chunk STS mismatch ($final_sts_data)"
    return 1
  fi
  if [ "$signature" != "63bddb248ad2590c92712055f51b8e78ab024eead08276b24f010b0efd74843f" ]; then
    log_rest 2 "final chunk signature mismatch ($signature)"
    return 1
  fi
}

record_command_lines() {
  while IFS= read -r line; do
    if ! mask_arg_array "$line"; then
      return 1
    fi
    # shellcheck disable=SC2154
    echo "${masked_args[*]}" >> "$COMMAND_LOG"
  done <<< "$command"
}

build_initial_command() {
  command="PUT /$bucket_name/$key HTTP/1.1\r
Host: $host\r
x-amz-date: $current_date_time\r
x-amz-storage-class: REDUCED_REDUNDANCY\r
Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer,Signature=$first_signature\r
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\r
Content-Encoding: aws-chunked\r
x-amz-decoded-content-length: $file_size\r
x-amz-trailer: $trailer\r
Content-Length: $content_length\r
\r\n"

if [ "$test_mode" == "true" ] && [ "$command" != "$expected_command" ]; then
  log_rest 2 "command mismatch ($command)"
  return 1
fi
  echo -en "$command" > "$COMMAND_FILE"
}

complete_command() {
  echo -e "\r" >> "$COMMAND_FILE"
  if [ -n "$COMMAND_LOG" ]; then
    if ! record_command_lines; then
      return 1
    fi
  fi
}

load_parameters

if ! calculate_checksum; then
  log_rest 2 "error calculating trailer checksum"
  exit 1
fi
if ! get_file_size_and_content_length; then
  log_rest 2 "error getting file size and content length"
  exit 1
fi

if ! get_first_signature; then
  log_rest 2 "error getting first signature"
  exit 1
fi

if ! build_initial_command; then
  log_rest 2 "error building command"
  exit 1
fi
if ! build_chunks "$first_signature"; then
  log_rest 2 "error building chunks"
  exit 1
fi
if ! build_trailer; then
  log_rest 2 "error building trailer"
  exit 1
fi
if [ "$test_mode" == "true" ]; then
  if ! check_final_signature; then
    log_rest 2 "error checking final chunks"
    exit 1
  fi
  log_rest 4 "TEST PASS"
fi
if ! complete_command; then
  log_rest 2 "error adding chunks"
  exit 1
fi
exit 0
