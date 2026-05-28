#!/usr/bin/env bash

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

check_prefixes_delimiters_and_keys() {
  if ! check_param_count_gt "data file, enclosing element, individual element, prefix, delimiter, common prefixes, --, keys" 6 $#; then
    return 1
  fi
  local response xml_data checking_prefixes="true" prefix_count=0 key_count=0

  if ! response=$(check_validity_and_or_parse_xml_data "$1" 2>&1); then
    log 2 "error parsing xml data: $response"
    return 1
  fi
  xml_data="$response"

  log 5 "XML data: $xml_data"
  for param in "${@:6}"; do
    if [ "$param" == "--" ]; then
      checking_prefixes=false
      continue
    fi
    if ! check_a_common_prefix_or_key "$xml_data" "$param" "$checking_prefixes" "$2" "$3"; then
      log 2 "error checking if common prefix or key '$param' exists"
      return 1
    fi
    if [ "$checking_prefixes" == "true" ]; then
      ((prefix_count++))
    else
      ((key_count++))
    fi
  done
  if ! check_prefixes_delimiter_and_counts "$xml_data" "$4" "$5" "$prefix_count" "$key_count" "$2" "$3"; then
    log 2 "error checking prefix"
    return 1
  fi
  return 0
}

check_a_common_prefix_or_key() {
  if ! check_param_count_v2 "data file, parameter, prefix or not, base element, unit element" 5 $#; then
    return 1
  fi
  if [ "$3" == "true" ]; then
    if ! check_if_element_exists "$1" "$2" "$4" "CommonPrefixes" "Prefix"; then
      log 2 "error checking if CommonPrefix '$2' exists"
      return 1
    fi
  else
    if ! check_if_element_exists "$1" "$2" "$4" "$5" "Key"; then
      log 2 "error checking if Key '$2' exists"
      return 1
    fi
  fi
  return 0
}

check_prefixes_delimiter_and_counts() {
  if ! check_param_count_v2 "data, prefix, delimiter, prefix count, key count, base element, unit element" 7 $#; then
    return 1
  fi
  if ! check_xml_element "$1" "$2" "$6" "Prefix"; then
    log 2 "error checking prefix"
    return 1
  fi
  if ! check_xml_element "$1" "$3" "$6" "Delimiter"; then
    log 2 "error checking delimiter"
    return 1
  fi
  if ! check_element_count "$1" "$4" "$6" "CommonPrefixes" "Prefix"; then
    log 2 "Prefix count mismatch"
    return 1
  fi
  if ! check_element_count "$1" "$5" "$6" "$7" "Key"; then
    log 2 "Key count mismatch"
    return 1
  fi
  return 0
}
