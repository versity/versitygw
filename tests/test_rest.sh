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

source ./tests/drivers/file.sh
source ./tests/drivers/params.sh
source ./tests/drivers/rest.sh
source ./tests/logger.sh
source ./tests/setup_unit.sh

@test "check_key_and_value_pair_for_match" {
  run check_key_and_value_pair_for_match "one" "two" "three"
  assert_failure 2

  run check_key_and_value_pair_for_match "one" "two" "one" "three"
  assert_failure 2

  run check_key_and_value_pair_for_match "one" "two" "three" "four"
  assert_failure 1

  run check_key_and_value_pair_for_match "one" "two two" "one" "two two"
  assert_success

  run check_key_and_value_pair_for_match "Content-Type" "application/xml" "content-type" "application/xml"
  assert_success

  run check_key_and_value_pair_for_match "one" "two" "one" "two"
  assert_success
}

@test "check_for_key_and_value_within_pairs" {
  # match in middle, omit it
  run check_for_key_and_value_within_pairs "B" "2" "A" "1" "B" "2" "C" "3"
  assert_success
  assert_output $'A\n1\nC\n3'

  # match first, omit it
  run check_for_key_and_value_within_pairs "A" "1" "A" "1" "B" "2" "C" "3"
  assert_success
  assert_output $'B\n2\nC\n3'

  # match last, omit it
  run check_for_key_and_value_within_pairs "C" "3" "A" "1" "B" "2" "C" "3"
  assert_success
  assert_output $'A\n1\nB\n2'

  # no match should fail
  run check_for_key_and_value_within_pairs "D" "9" "A" "1" "B" "2" "C" "3"
  assert_failure 1

  # key match but value mismatch should fail
  run check_for_key_and_value_within_pairs "B" "999" "A" "1" "B" "2" "C" "3"
  assert_failure 2

  # duplicate exact pairs; omit only the last matching pair
  run check_for_key_and_value_within_pairs "A" "2" "A" "2" "A" "2" "B" "3"
  assert_success
  assert_output $'A\n2\nB\n3'

  # odd number of pair args should fail
  run check_for_key_and_value_within_pairs "A" "1" "A" "1" "B"
  assert_failure 2
}

@test "check_header_keys_and_values" {
  run get_file_name
  assert_success
  resp_file="$TEST_FILE_FOLDER/$output"

  # 1) Exact match, single header
  run bash -c "printf 'HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n<body/>' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "Content-Type" "application/xml"
  assert_success

  # 2) Header value contains spaces
  run bash -c "printf 'HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"a b.txt\"\r\n\r\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "Content-Disposition" 'attachment; filename="a b.txt"'
  assert_success

  # 3) Empty header value allowed
  run bash -c "printf 'HTTP/1.1 200 OK\r\nX-Empty:\r\n\r\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "X-Empty" ""
  assert_success

  # 4) Missing expected header should fail
  run bash -c "printf 'HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "ETag" '"abc"'
  assert_failure

  # 5) Value mismatch should fail
  run bash -c "printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "Content-Type" "application/xml"
  assert_failure

  # 6) Multiple expected headers, any order
  run bash -c "printf 'HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Type: application/xml\r\n\r\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "Content-Type" "application/xml" "ETag" '"abc"'
  assert_success

  # 7) Stop parsing at blank line (body contains ':' should not be treated as header)
  run bash -c "printf 'HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\nNotAHeader: still body\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "Content-Type" "application/xml"
  assert_success

  # 8) Key case-insensitivity
  run bash -c "printf 'HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\n\r\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "Content-Type" "application/xml"
  assert_success

  # middle header key/value
  run bash -c "printf 'HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\ndummy-header: dummy-val\r\nanother-dummy-header: another-val\r\n\r\n' > '$resp_file'"
  assert_success
  run check_header_keys_and_values "$resp_file" "Dummy-Header" "dummy-val"
  assert_success
}
