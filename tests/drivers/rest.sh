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

source ./tests/util/util_xml.sh

check_rest_expected_error() {
  if ! check_param_count_v2 "response, response file, expected http code, expected error code, expected error" 5 $#; then
    return 1
  fi
  if [ "$1" != "$3" ]; then
    log 2 "expected '$3', was '$1' ($(cat "$2"))"
    return 1
  fi
  if ! check_xml_error_contains "$2" "$4" "$5"; then
    log 2 "error checking XML response"
    return 1
  fi
  return 0
}