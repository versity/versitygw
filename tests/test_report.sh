#!/usr/bin/env bats

# Copyright 2026 Versity Software
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
source ./tests/setup_unit.sh

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
  expected_results=("BUCKET" "OBJECT" "MAIN" "UNKNOWN")

  for ((i=0; i<${#tests[@]}; i++)); do
    echo "test: ${tests[$i]}, expected result: ${expected_results[$i]}"
    run parse_path_and_get_route "${tests[$i]}"
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
          x-amz-content-sha256:UNSIGNED-PAYLOAD"
          "PUT /bucket/file?prefix=dummy HTTP/1.1
          Authorization: AWS4-HMAC-SHA256 Credential=AKIAQJVWFRZQNI6LF3W7/20250911/us-east-1/s3/aws4_request,SignedHeaders=x-amz-content-sha256;x-amz-date,Signature=86ffbe2317caddcac569b25aa9b8e8db4a613a639b2a402cf4a9dc0e975ba997
          x-amz-content-sha256:UNSIGNED-PAYLOAD")
  expected_output=("GET MAIN " "PUT OBJECT prefix")

  for ((i=0; i<${#tests[@]}; i++)); do
    if file_name=$(get_file_name_with_prefix "openssl" 2>&1); then
      return 1
    fi
    echo "${tests[$i]}" > "$file_name"
    run get_openssl_method_route_queries "$file_name"
    assert_output "${expected_output[$i]}"
  done
}

@test "report - check for copy header value" {
  test_clients=("OPENSSL" "OPENSSL" "CURL" "CURL" "CUR")
  test_data=("GET / HTTP/1.1
            Authorization: AWS4-HMAC-SHA256 Credential=AKIAQJVWFRZQNI6LF3W7/20250911/us-east-1/s3/aws4_request,SignedHeaders=x-amz-content-sha256;x-amz-date,Signature=86ffbe2317caddcac569b25aa9b8e8db4a613a639b2a402cf4a9dc0e975ba997
            x-amz-content-sha256:UNSIGNED-PAYLOAD"
            "PUT /bucket/file?prefix=dummy HTTP/1.1
            Authorization: AWS4-HMAC-SHA256 Credential=AKIAQJVWFRZQNI6LF3W7/20250911/us-east-1/s3/aws4_request,SignedHeaders=x-amz-content-sha256;x-amz-date,Signature=86ffbe2317caddcac569b25aa9b8e8db4a613a639b2a402cf4a9dc0e975ba997
            x-amz-copy-source:something"
            "curl -ks -w %{http_code} -X PUT https://localhost:7070/versity-gwtest-bucket-one-1-20260129133816/test-file-ED302D34-1A3F-47D5-B3B7-78DF01943C29-copy -H Authorization: AWS4-HMAC-SHA256 Credential=AKIA6****/20260129/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-copy-source;x-amz-date,Signature=59091238ab6f297fa79201c90c2e77707177942ef1ba1c78ba31ec735f109477 -H host: localhost:7070 -H x-amz-content-sha256: UNSIGNED-PAYLOAD -H x-amz-copy-source: versity-gwtest-bucket-one-1-20260129133816/test-file-ED302D34-1A3F-47D5-B3B7-78DF01943C29 -H x-amz-date: 20260129T163817Z -o /Users/lukemccrone/devel/versitygw/versity-gwtest-files/result.txt -T /Users/lukemccrone/devel/versitygw/versity-gwtest-files/test-file-ED302D34-1A3F-47D5-B3B7-78DF01943C29"
            "curl -ks -w %{http_code} -X PUT https://localhost:7070/versity-gwtest-bucket-one-1-20260129133816/test-file-ED302D34-1A3F-47D5-B3B7-78DF01943C29 -H Authorization: AWS4-HMAC-SHA256 Credential=AKIA6****/20260129/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=3f0d83d829b502ed3e5d7c66de109151df10ce76e866def1ccdd46e48bde66ca -H host: localhost:7070 -H x-amz-content-sha256: 778e1535066c2e3def76239d1326c019f5548480d68fd13a1d68942b1eb1b6c5 -H x-amz-date: 20260129T163817Z -T /Users/lukemccrone/devel/versitygw/versity-gwtest-files/test-file-ED302D34-1A3F-47D5-B3B7-78DF01943C29 -o /Users/lukemccrone/devel/versitygw/versity-gwtest-files/output.txt"
            "curl -ks -w %{http_code} -X PUT https://localhost:7070/versity-gwtest-bucket-one-1-20260129133816/test-file-ED302D34-1A3F-47D5-B3B7-78DF01943C29 -H Authorization: AWS4-HMAC-SHA256 Credential=AKIA6****/20260129/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=3f0d83d829b502ed3e5d7c66de109151df10ce76e866def1ccdd46e48bde66ca -H host: localhost:7070 -H x-amz-content-sha256: 778e1535066c2e3def76239d1326c019f5548480d68fd13a1d68942b1eb1b6c5 -H x-amz-date: 20260129T163817Z -T /Users/lukemccrone/devel/versitygw/versity-gwtest-files/test-file-ED302D34-1A3F-47D5-B3B7-78DF01943C29 -o /Users/lukemccrone/devel/versitygw/versity-gwtest-files/output.txt")
  expected_responses=(1 0 0 1 2)

  for ((i=0; i<${#test_clients[@]}; i++)); do
    echo "test $i"
    if [ "${test_clients[$i]}" == "OPENSSL" ]; then
      if file_name=$(get_file_name_with_prefix "openssl" 2>&1); then
        return 1
      fi
      echo "${test_data[$i]}" > "$file_name"
      data_param=$file_name
    else
      data_param=${test_data[$i]}
    fi
    run check_for_copy_source "${test_clients[$i]}" "$data_param"
    if [ "${expected_responses[$i]}" -eq 0 ]; then
      assert_success
    else
      assert_failure "${expected_responses[$i]}"
    fi
  done
}
