#!/usr/bin/env bats

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

load ./bats-support/load
load ./bats-assert/load

source ./tests/logger.sh
source ./tests/report.sh

@test "reporting - parse curl method" {
  tests=(" -Iks" "" " -X PUT" " -X DELETE")
  expected_results=("HEAD" "GET" "PUT" "DELETE")

  for ((i=0; i<${#tests[@]}; i++)); do
    echo "test: ${tests[$i]}, expected result: ${expected_results[$i]}"
    run get_curl_method "${tests[$i]}"
    assert_output "${expected_results[$i]}"
  done
}

@test "reporting - parse curl route" {
  tests=("http://localhost:7070/bucket_name" "http://localhost:7070/bucket_name/file_name" "http://localhost:7070/" "")
  expected_results=("BUCKET" "FILE" "MAIN" "UNKNOWN")

  for ((i=0; i<${#tests[@]}; i++)); do
    echo "test: ${tests[$i]}, expected result: ${expected_results[$i]}"
    run get_curl_route "${tests[$i]}"
    assert_output "${expected_results[$i]}"
  done
}

@test "reporting - get query" {
  tests=("https://localhost:7070/?query1=" "https://localhost/bucket?another=" "https://1.2.3.4/" "http://localhost/bucket/file?third")
  expected_results=("query1" "another" "" "third")

  for ((i=0; i<${#tests[@]}; i++)); do
    echo "test: ${tests[$i]}, expected result: ${expected_results[$i]}"
    run get_query "${tests[$i]}"
    assert_output "${expected_results[$i]}"
  done
}

@test "reporting - get client type" {
  tests=("curl -iks https://localhost:7070/versity-gwtest-bucket-one-1-20260127113351?location= -H Authorization: AWS4-HMAC-SHA256 Credential=AKIA6****/20260127/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=68c0b96180a5791be8a10335c10d302d31d358c4bc6028aec94faf502f3a185e -H host: localhost:7070 -H x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -H x-amz-date: 20260127T143355Z" \
    "aws --no-verify-ssl s3api create-bucket --bucket versity-gwtest-bucket-one-1-20260127113351 --object-lock-enabled-for-bucket" "")
  expected_results=("CURL" "S3API" "UNKNOWN")

  for ((i=0; i<${#tests[@]}; i++)); do
    run get_client_type "${tests[$i]}"
    assert_output "${expected_results[$i]}"
  done
}

@test "reporting - parse curl rest command" {
  tests=("curl -iks https://localhost:7070/versity-gwtest-bucket-one-1-20260127113351?location= -H Authorization: AWS4-HMAC-SHA256 Credential=AKIA6****/20260127/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=68c0b96180a5791be8a10335c10d302d31d358c4bc6028aec94faf502f3a185e -H host: localhost:7070 -H x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -H x-amz-date: 20260127T143355Z")
  expected_command=("GET BUCKET location")

  for ((i=0; i<${#tests[@]}; i++)); do
    run parse_curl_rest_command "${tests[$i]}"
    assert_output "${expected_command[$i]}"
  done
}

@test "openssl - get method, route, and queries" {
  tests=("GET / HTTP/1.1
          Authorization: AWS4-HMAC-SHA256 Credential=AKIAQJVWFRZQNI6LF3W7/20250911/us-east-1/s3/aws4_request,SignedHeaders=x-amz-content-sha256;x-amz-date,Signature=86ffbe2317caddcac569b25aa9b8e8db4a613a639b2a402cf4a9dc0e975ba997
          x-amz-content-sha256:UNSIGNED-PAYLOAD")
  expected_output=("GET MAIN ")

  for ((i=0; i<${#tests[@]}; i++)); do
    file_name="$TMPDIR/openssl-$(uuidgen)"
    echo "${tests[$i]}" > "$file_name"
    run get_openssl_method_route_queries "$file_name"
    assert_output "${expected_output[$i]}"
  done
}