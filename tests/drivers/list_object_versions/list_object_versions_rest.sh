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

parse_version_id() {
  if ! check_param_count_v2 "data file, IsLatest val" 2 $#; then
    return 1
  fi
  log 5 "data: $(cat "$1")"
  version_string="//*[local-name()=\"Version\"][*[local-name()=\"IsLatest\" and text()=\"$2\"]]"
  log 5 "match string: $version_string"
  if ! get_xml_data "$1" "$1.xml"; then
    log 2 "error getting XML data"
    return 1
  fi
  if ! version=$(xmllint --xpath "$version_string" "$1.xml" 2>&1); then
    log 2 "error getting result: $version"
    return 1
  fi
  log 5 "latest: $2, version: $version"
  if ! version_id=$(xmllint --xpath "//*[local-name()=\"VersionId\"]/text()" <(echo "$version" | head -n 1) 2>&1); then
    log 2 "error getting version ID: $version_id"
    return 1
  fi
  log 5 "version ID: $version_id"
  return 0
}

parse_non_latest_version_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! parse_version_id "$1" "false"; then
    log 2 "error getting non-latest version ID"
    return 1
  fi
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

check_object_versions_before_deletion() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! get_xml_data "$1" "$1.tmp"; then
    log 2 "error getting XML data"
    return 1
  fi
  if ! parse_versions_rest "$1.tmp"; then
    log 2 "error parsing versions"
    return 1
  fi
  if [ "${#version_ids[@]}" -ne 1 ]; then
    log 2 "expected version ID count of 1, was '${#version_ids[@]}'"
    return 1
  fi
  version_id="${version_ids[0]}"
  log 5 "version ID: $version_id"
  return 0
}

check_object_versions_after_deletion() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! get_xml_data "$1" "$1.tmp"; then
    log 2 "error getting XML data"
    return 1
  fi
  if ! parse_versions_rest "$1.tmp"; then
    log 2 "error parsing versions"
    return 1
  fi
  if [ "${#version_ids[@]}" -ne 2 ]; then
    log 2 "expected version ID count of 2, was '${#version_ids[@]}'"
    return 1
  fi
  if [ "${version_ids[0]}" != "$version_id" ]; then
    log 2 "expected version ID of '$version_id', was '${version_ids[0]}'"
    return 1
  fi
  if [ "${version_islatests[0]}" != "false" ]; then
    log 2 "expected 'IsLatest' of version ID to be false, was '${version_islatests[0]}'"
    return 1
  fi
  if [ "${version_islatests[1]}" != "true" ]; then
    log 2 "expected 'IsLatest' of delete marker to be true, was '${version_islatests[1]}'"
    return 1
  fi
  return 0
}

list_object_versions_before_and_after_retention_deletion() {
  if ! check_param_count_v2 "bucket name, file" 2 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_object_versions_before_deletion" \
      "-method" "GET" "-bucketName" "$1" "-query" "versions="; then
    log 2 "error checking versions before deletion"
    return 1
  fi
  if ! delete_object_rest "$1" "$2"; then
    log 2 "error deleting file"
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_object_versions_after_deletion" \
      "-method" "GET" "-bucketName" "$1" "-query" "versions="; then
    log 2 "error checking versions before deletion"
    return 1
  fi
  return 0
}

parse_latest_version_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! parse_version_id "$1" "true"; then
    log 2 "error getting latest version ID"
    return 1
  fi
  log 5 "version ID: $version_id"
  return 0
}
