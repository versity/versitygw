#!/usr/bin/env bats

# Copyright 2025 Versity Software
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

source ./tests/drivers/xml.sh

check_policy_status() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  log 5 "data: $(cat "$1")"
  if ! check_xml_element "$1" "$expected_policy_status" "PolicyStatus" "IsPublic"; then
    log 2 "error checking policy status"
    return 1
  fi
  return 0
}

get_and_check_policy_status() {
  if ! check_param_count_v2 "bucket, expected status" 2 $#; then
    return 1
  fi
  expected_policy_status="$2"
  if ! send_rest_go_command_callback "200" "check_policy_status" "-bucketName" "$1" "-query" "policyStatus="; then
    log 2 "error sending REST go command or checking callback"
    return 1
  fi
  return 0
}