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

}