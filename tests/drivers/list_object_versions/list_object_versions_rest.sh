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

parse_non_latest_version_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  log 5 "data: $(cat "$1")"
  not_latest_string="//*[local-name()=\"Version\"][*[local-name()=\"IsLatest\" and text()=\"false\"]]"
  log 5 "match string: $not_latest_string"
  if ! get_xml_data "$1" "$1.xml"; then
    log 2 "error getting XML data"
    return 1
  fi
  if ! not_latest=$(xmllint --xpath "$not_latest_string" "$1.xml" 2>&1); then
    log 2 "error getting result: $not_latest"
    return 1
  fi
  log 5 "not latest: $not_latest"
  if ! version_id=$(xmllint --xpath "//*[local-name()=\"VersionId\"]/text()" <(echo "$not_latest" | head -n 1) 2>&1); then
    log 2 "error getting version ID: $version_id"
    return 1
  fi
  log 5 "version ID: $version_id"
  return 0
}

get_non_latest_version() {
  if ! check_param_count_v2 "bucket" $# 1; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "parse_non_latest_version_id" "-method" "GET" "-query" "versions=" "-bucketName" "$1"; then
    log 2 "error retrieving version tags"
    return 1
  fi
  return 0
}
