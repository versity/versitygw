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

source ./tests/util/util_xml.sh

send_via_openssl() {
  if ! check_param_count_v2 "command file" 1 $#; then
    return 1
  fi
  host="${AWS_ENDPOINT_URL#http*://}"
  if [[ "$host" =~ s3\..*amazonaws\.com ]]; then
    host+=":443"
  fi
  log 5 "connecting to $host"
  if ! result=$(openssl s_client -connect "$host" -ign_eof < "$1" 2>&1); then
    log 2 "error sending openssl command: $result"
    return 1
  fi
  echo "$result"
}

send_via_openssl_and_check_code() {
  if ! check_param_count_v2 "command file, expected code" 2 $#; then
    return 1
  fi
  if ! result=$(send_via_openssl "$1"); then
    log 2 "error sending command via openssl"
    return 1
  fi
  response_code="$(echo "$result" | grep "HTTP/" | awk '{print $2}')"
  if [ "$response_code" != "$2" ]; then
    log 2 "expected '$2', actual '$response_code' (error response:  '$result')"
    return 1
  fi
  echo "$result"
}

send_via_openssl_check_code_error_contains() {
  if ! check_param_count_v2 "command file, expected code, error, message" 4 $#; then
    return 1
  fi
  if ! result=$(send_via_openssl_and_check_code "$1" "$2"); then
    log 2 "error sending and checking code"
    return 1
  fi
  echo -n "$result" > "$TEST_FILE_FOLDER/result.txt"
  if ! get_xml_data "$TEST_FILE_FOLDER/result.txt" "$TEST_FILE_FOLDER/error_data.txt"; then
    log 2 "error parsing XML data from result"
    return 1
  fi
  if ! check_xml_error_contains "$TEST_FILE_FOLDER/error_data.txt" "$3" "$4"; then
    log 2 "error checking xml error, message"
    return 1
  fi
  return 0
}

send_via_openssl_with_timeout() {
  if ! check_param_count_v2 "command file" 1 $#; then
    return 1
  fi
  host="${AWS_ENDPOINT_URL#http*://}"
  if [[ "$host" =~ s3\..*amazonaws\.com ]]; then
    host+=":443"
  fi
  log 5 "connecting to $host"
  local exit_code=0
  result=$(timeout 65 openssl s_client -connect "$host" -ign_eof < "$1" 2>&1) || exit_code=$?
  if [ "$exit_code" == 124 ]; then
    log 2 "error:  openssl command timed out"
    return 1
  elif [ "$exit_code" != 0 ]; then
    log 2 "error sending openssl command: exit code $exit_code, $result"
    return 1
  fi
  if ! [[ "$result" =~ .*$'\nclosed' ]]; then
    log 2 "connection not closed properly: $result"
    return 1
  fi
  return 0
}
