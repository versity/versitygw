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
  no_content_length="${NO_CONTENT_LENGTH:=false}"

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
  fi

  readonly initial_sts_data="AWS4-HMAC-SHA256-PAYLOAD
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
cee3fed04b70f867d036f722359b0b1f2f0e5dc0efadbc082b76c4c60e316455"

  readonly expected_sts_chunk_one="AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a"

  readonly expected_sts_chunk_two="AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a"

  readonly expected_sts_chunk_three="AWS4-HMAC-SHA256-PAYLOAD
20130524T000000Z
20130524/us-east-1/s3/aws4_request
0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  readonly expected_canonical_request="PUT
/examplebucket/chunkObject.txt

content-encoding:aws-chunked
content-length:66824
host:s3.amazonaws.com
x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD
x-amz-date:20130524T000000Z
x-amz-decoded-content-length:66560
x-amz-storage-class:REDUCED_REDUNDANCY

content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class
STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

  readonly expected_command="PUT /examplebucket/chunkObject.txt HTTP/1.1\r
Host: s3.amazonaws.com\r
x-amz-date: 20130524T000000Z\r
x-amz-storage-class: REDUCED_REDUNDANCY\r
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9\r
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r
Content-Encoding: aws-chunked\r
x-amz-decoded-content-length: 66560\r
Content-Length: 66824\r
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
  content_length=$((length+file_size))
  if [ "$test_mode" == "true" ] && [ "$content_length" != 66824 ]; then
    log_rest 2 "content length mismatch ($content_length)"
    return 1
  fi
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
content-length:$content_length
host:$host
x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD
x-amz-date:$current_date_time
"
if [ "$no_content_length" == "false" ]; then
  canonical_request+="x-amz-decoded-content-length:$file_size
"
else
  canonical_request+="x-amz-decoded-content-length:
"
fi
canonical_request+="x-amz-storage-class:REDUCED_REDUNDANCY

content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class
STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

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
    if [ "$first_signature" != "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9" ]; then
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
      check_chunks_and_signatures_in_test_mode $idx
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
      if [ "$signature" != "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648" ]; then
        log_rest 2 "first chunk signature mismatch ($signature)"
        return 1
      fi
      ;;
    1)
      if [ "$chunk_sts_data" != "$expected_sts_chunk_two" ]; then
        log_rest 2 "second chunk STS mismatch ($chunk_sts_data)"
        return 1
      fi
      if [ "$signature" != "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497" ]; then
        log_rest 2 "second chunk signature mismatch ($signature)"
        return 1
      fi
      ;;
    2)
      if [ "$chunk_sts_data" != "$expected_sts_chunk_three" ]; then
        log_rest 2 "final chunk STS mismatch ($chunk_sts_data)"
        return 1
      fi
      if [ "$signature" != "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9" ]; then
        log_rest 2 "final chunk signature mismatch ($signature)"
        return 1
      fi
      ;;
  esac
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
Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=$first_signature\r
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r
Content-Encoding: aws-chunked\r
"
if [ "$no_content_length" == "false" ]; then
  command+="x-amz-decoded-content-length: $file_size\r
"
fi
command+="Content-Length: $content_length\r
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
if ! complete_command; then
  log_rest 2 "error adding chunks"
  exit 1
fi

if [ "$test_mode" == "true" ]; then
  log_rest 4 "TEST PASS"
fi
exit 0
