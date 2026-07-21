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

parse_version_or_delete_marker_id() {
  if ! check_param_count_v2 "data file, 'Version' or 'DeleteMarker', IsLatest val" 3 $#; then
    return 1
  fi
  log 5 "data: $(cat "$1")"
  version_string="//*[local-name()=\"$2\"][*[local-name()=\"IsLatest\" and text()=\"$3\"]]"
  log 5 "match string: $version_string"
  if ! get_xml_data "$1" "$1.xml"; then
    log 2 "error getting XML data"
    return 1
  fi
  if ! version_or_marker=$(xmllint --xpath "$version_string" "$1.xml" 2>&1); then
    log 2 "error getting result: $version_or_marker"
    return 1
  fi
  log 5 "latest: $3, version or marker: $version_or_marker"
  if ! version_or_marker_id=$(xmllint --xpath "//*[local-name()=\"VersionId\"]/text()" <(echo "$version_or_marker" | head -n 1) 2>&1); then
    log 2 "error getting version ID: $version_or_marker_id"
    return 1
  fi
  log 5 "version or marker ID: $version_or_marker_id"
  echo "$version_or_marker_id"
  return 0
}

parse_version_id() {
  if ! check_param_count_v2 "data file, IsLatest val" 2 $#; then
    return 1
  fi
  if ! version_id=$(parse_version_or_delete_marker_id "$1" "Version" "$2" 2>&1); then
    echo "error parsing version ID: $version_id"
    return 1
  fi
  echo "$version_id"
  return 0
}

parse_a_non_latest_version_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi

  local response
  if ! response=$(parse_version_id "$1" "false" 2>&1); then
    log 2 "error getting non-latest version ID: $response"
    return 1
  fi

  version_id="$response"
  echo "$version_id"
  return 0
}

get_a_non_latest_version() {
  if ! check_param_count_v2 "bucket" $# 1; then
    return 1
  fi

  local response
  if ! response=$(send_rest_go_command_callback "200" "parse_a_non_latest_version_id" "-method" "GET" "-query" "versions=" "-bucketName" "$1" 2>&1); then
    log 2 "error retrieving non-latest version ID: $response"
    return 1
  fi

  non_latest_version="$response"
  echo "$non_latest_version"
  return 0
}

check_object_versions_before_deletion() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi

  local response
  if ! response=$(check_validity_and_or_parse_xml_data "$1" 2>&1); then
    log 2 "error getting XML data: $response"
    return 1
  fi

  xml_data="$response"
  if ! parse_versions_rest "$xml_data"; then
    log 2 "error parsing versions"
    return 1
  fi
  # shellcheck disable=SC2154
  if [ "${#version_ids[@]}" -ne 1 ]; then
    log 2 "expected version ID count of 1, was '${#version_ids[@]}'"
    return 1
  fi
  version_id="${version_ids[0]}"
  log 5 "version ID: $version_id"
  echo "$version_id"
  return 0
}

check_object_versions_after_deletion() {
  if ! check_param_count_v2 "data file, version ID" 2 $#; then
    return 1
  fi

  local response xml_data
  if ! response=$(check_validity_and_or_parse_xml_data "$1" 2>&1); then
    log 2 "error getting XML data: $response"
    return 1
  fi

  xml_data="$response"
  if ! parse_versions_rest "$xml_data"; then
    log 2 "error parsing versions"
    return 1
  fi
  if [ "${#version_ids[@]}" -ne 2 ]; then
    log 2 "expected version ID count of 2, was '${#version_ids[@]}'"
    return 1
  fi
  if [ "${version_ids[0]}" != "$2" ]; then
    log 2 "expected version ID of '$2', was '${version_ids[0]}'"
    return 1
  fi
  # shellcheck disable=SC2154
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
  if ! key_version_id=$(send_rest_go_command_callback "200" "check_object_versions_before_deletion" \
      "-method" "GET" "-bucketName" "$1" "-query" "versions=" 2>&1); then
    log 2 "error checking versions before deletion"
    return 1
  fi
  if ! delete_object_rest "$1" "$2"; then
    log 2 "error deleting file"
    return 1
  fi
  log 5 "version ID: $key_version_id"
  if ! send_rest_go_command_callback "200" "check_object_versions_after_deletion" \
      "-method" "GET" "-bucketName" "$1" "-query" "versions=" "--" "$key_version_id"; then
    log 2 "error checking versions after deletion"
    return 1
  fi
  return 0
}

parse_latest_version_id() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi

  local response
  if ! response=$(parse_version_id "$1" "true" 2>&1); then
    log 2 "error getting latest version ID: $response"
    return 1
  fi

  version_id="$response"
  log 5 "version ID: $version_id"
  echo "$version_id"
  return 0
}

check_page_with_two_different_keys() {
  if ! check_param_count_ge_le "data file, version ID marker, version ID, next version ID marker (optional)" 3 4 $#; then
    return 1
  fi
  if ! check_version_page_order "$1" "KeyMarker" "Key" "NextKeyMarker" "$2" "$3" "$4"; then
    log 2 "error checking pages for different keys"
    return 1
  fi
  return 0
}

parse_version_ids_with_same_key() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  local response versions version_id

  if ! response=$(get_element "$1" "ListVersionsResult" "Version" 2>&1); then
    log 2 "error getting version: $response"
    return 1
  fi
  log 5 "versions: $response"
  mapfile -t versions <<< "$response"

  for version in "${versions[@]}"; do
    if ! response=$(get_element_text_inside_string "$version" "VersionId" 2>&1); then
      log 2 "error getting VersionId element: $response"
      return 1
    fi
    version_id="$response"
    echo "$version_id"
  done
  return 0
}

check_page_order_of_version_ids_with_same_key() {
  if ! check_param_count_ge_le "data file, version ID marker, version ID, next version ID marker (optional)" 3 4 $#; then
    return 1
  fi
  if ! check_version_page_order "$1" "VersionIdMarker" "VersionId" "NextVersionIdMarker" "$2" "$3" "$4"; then
    log 2 "error checking pages for same key, different version IDs"
    return 1
  fi
  return 0
}

check_version_page_order() {
  if ! check_param_count_ge_le "data file, previous marker name, value name, next marker name, prev value, value, next value" 6 7 $#; then
    return 1
  fi
  if ! response=$(check_validity_and_or_parse_xml_data "$1" 2>&1); then
    log 2 "error getting XML data: $response"
    return 1
  fi
  xml_data="$response"

  if ! check_xml_element "$xml_data" "$5" "ListVersionsResult" "$2"; then
    log 2 "error checking KeyMarker element"
    return 1
  fi
  if ! check_xml_element "$xml_data" "$6" "ListVersionsResult" "Version" "$3"; then
    log 2 "error checking Key element"
    return 1
  fi
  if [ $# -lt 7 ]; then
    if ! check_for_empty_element "$xml_data" "ListVersionsResult" "$4"; then
      log 2 "error checking for empty NextKeyMarker"
      return 1
    fi
  else
    if ! check_xml_element "$xml_data" "$7" "ListVersionsResult" "$4"; then
      log 2 "error checking NextKeyMarker element"
      return 1
    fi
  fi
  return 0
}

list_object_versions_with_prefix_and_delimiter_check_results() {
  if ! check_param_count_gt "bucket name, prefix, delimiter, expected common prefixes, --, expected keys" 6 $#; then
    return 1
  fi
  if ! send_rest_go_command_callback "200" "check_prefixes_delimiters_and_keys" "-bucketName" "$1" "-query" "versions&delimiter=$3&prefix=$2" "--" "ListVersionsResult" "Version" "${@:2}"; then
    log 2 "error sending command to list objects or receiving response"
    return 1
  fi
  return 0
}

get_xml_versions_data() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  local data_file="$1"
  local response

  if ! response=$(get_element "$data_file" "ListVersionsResult" 2>&1); then
    log 2 "error getting ListVersionsResult: $response"
    return 1
  fi
  printf '%s\n' "$response"
  return 0
}
