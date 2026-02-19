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

build_xpath_string() {
  if ! check_param_count_gt "XML tree" 1 $#; then
    return 1
  fi
  if ! build_xpath_string_for_element "$@"; then
    return 1
  fi
  xpath+='/text()'
}

build_xpath_string_for_element() {
  if ! check_param_count_gt "XML tree" 1 $#; then
    return 1
  fi
  local xpath='//'
  for ((idx=1;idx<=$#;idx++)); do
    if [ "${!idx}" == "" ]; then
      log 2 "param number $idx is empty"
      return 1
    fi
    if [[ "${!idx}" =~ [[:space:]] ]]; then
      log 2 "param '${!idx}' contains a space"
      return 1
    fi
    xpath+='*[local-name()="'${!idx}'"]'
    if [ "$idx" != $# ]; then
      xpath+='/'
    fi
  done
  echo "$xpath"
  return 0
}

check_for_empty_element() {
  if ! check_param_count_gt "data file, XML tree" 2 $#; then
    return 1
  fi

  # shellcheck disable=SC2068
  if ! xpath=$(build_xpath_string_for_element ${@:2} 2>&1); then
    log 2 "error building XPath search string: $xpath"
    return 1
  fi
  if ! get_xml_data "$1" "$1.xml"; then
    log 2 "error getting XML data"
    return 1
  fi
  if grep -q '<[^/][^ >]*>' "$1.xml"; then
    if xmllint --xpath "${xpath}[not(normalize-space())]" "$1.xml" 1>/dev/null 2>&1; then
      return 0
    fi
  fi
  return 1
}

get_element() {
  if ! check_param_count_gt "data file, XML tree" 2 $#; then
    return 1
  fi

  if ! xpath=$(build_xpath_string_for_element "${@:2}" 2>&1); then
    log 2 "error building XPath search string"
    return 1
  fi
  if ! xml_val=$(grep '<[^/][^ >]*>' "$1" | xmllint --xpath "$xpath" - 2>&1); then
    log 2 "error getting XML value matching $xpath: $xml_val (file data: $(cat "$1"))"
    return 1
  fi
  echo "$xml_val"
}

get_element_text() {
  if ! check_param_count_gt "data file, XML tree" 2 $#; then
    return 1
  fi

  if ! xpath=$(build_xpath_string_for_element "${@:2}" 2>&1); then
    log 2 "error building XPath search string: $xpath"
    return 1
  fi

  log 5 "data: $(cat "$1")"
  log 5 "xpath: $xpath"
  if ! get_xml_data "$1" "$1.xml"; then
    log 2 "error getting XML data"
    return 1
  fi
  log 5 "result: $(xmllint --xpath "boolean($xpath)" "$1.xml" 2>&1)"
  result=$(xmllint --xpath "boolean($xpath)" "$1.xml" 2>&1)
  if [ "$result" == "false" ]; then
    log 2 "element matching '$xpath' doesn't exist"
    return 1
  fi
  if ! xml_val=$(xmllint --xpath "${xpath}/text()" "$1.xml" 2>/dev/null); then
    echo ""
    return 0
  fi
  echo "$xml_val"
}

check_xml_element() {
  if [ $# -lt 3 ]; then
    log 2 "'check_xml_element' requires data source, expected value, XML tree"
    return 1
  fi
  if ! xml_val=$(get_element_text "$1" "${@:3}"); then
    log 2 "error getting element text"
    return 1
  fi
  if [ "$2" != "$xml_val" ]; then
    log 2 "XML data mismatch, expected '$2', actual '$xml_val'"
    return 1
  fi
  return 0
}

check_xml_element_contains() {
  if [ $# -lt 3 ]; then
    log 2 "'check_xml_element_contains' requires data source, expected value, XML tree"
    return 1
  fi
  if [ "$2" == "" ]; then
    if ! check_for_empty_element "$1" "${@:3}"; then
      log 2 "Message value not empty"
      return 1
    fi
    return 0
  else
    if ! xml_val=$(get_element_text "$1" "${@:3}"); then
      log 2 "error getting element text"
      return 1
    fi
  fi
  if [[ "$xml_val" != *"$2"* ]]; then
    log 2 "XML data mismatch, expected '$2', actual '$xml_val'"
    return 1
  fi
  return 0
}

check_xml_error_contains() {
  if [ "$#" -ne 3 ]; then
    log 2 "'check_xml_code_error_contains' requires data source, expected error, string"
    return 1
  fi
  if ! check_xml_element "$1" "$2" "Error" "Code"; then
    log 2 "error checking xml error code"
    return 1
  fi
  if ! check_xml_element_contains "$1" "$3" "Error" "Message"; then
    log 2 "error checking xml element"
    return 1
  fi
  return 0
}

check_xml_error_contains_with_single_error_field() {
  if ! check_param_count_v2 "data source, expected error, string, expected key, expected value" 5 $#; then
    return 1
  fi
  if ! check_xml_error_contains "$1""$2" "$3"; then
    log 2 "error checking initial xml error"
    return 1
  fi
  if ! check_error_parameter "$1" "$4" "$5"; then
    log 2 "error checking error parameter"
    return 1
  fi
  return 0
}

check_if_element_exists() {
  if ! check_param_count_gt "data file, element, XML tree" 3 $#; then
    return 1
  fi
  if ! xpath=$(build_xpath_string_for_element "${@:3}" 2>&1); then
    log 2 "error building XPath search string: $xpath"
    return 1
  fi

  log 5 "data: $(cat "$1")"
  log 5 "xpath: $xpath"
  if ! get_xml_data "$1" "$1.xml"; then
    log 2 "error getting XML data"
    return 1
  fi
  if ! result=$(xmllint --xpath "boolean(${xpath}[text()='$2'])" "$1.xml" 2>&1); then
    log 2 "error getting result: $result"
    return 1
  fi
  if [ "$result" == "true" ]; then
    return 0
  fi
  return 1
}

get_xml_data() {
  if ! check_param_count_v2 "data file, output file" 2 $#; then
    return 1
  fi

  if [ ! -e "$1" ]; then
    log 2 "file '$1' does not exist"
    return 1
  fi
  log 5 "data: $(cat "$1")"

  # Find first line with "<?xml" and everything from there onward
  xml_start=$(grep -n "<?xml" "$1" | head -n 1 | cut -d: -f1)

  if [ -z "$xml_start" ]; then
    # Try any tag
    xml_start=$(grep -n "<[^>]*>" "$1" | head -n 1 | cut -d: -f1)
    if [ -z "$xml_start" ]; then
      log 2 "No XML declaration found."
      return 1
    fi
  fi
  log 5 "xml start: $xml_start"

  # Grab everything from the XML start line to the end of the file
  tail -n +"$xml_start" "$1" > "$2"
  log 5 "xml data after start: $(cat "$2")"

  # Try to extract valid XML using xmllint recover mode
  # This will truncate anything after the root closing tag
  truncated=$(xmllint --recover --noent --nocdata "$2" 2>/dev/null |
    awk 'BEGIN{xml=0}
         /<\?xml/{xml=1}
         {if (xml) print}
         /<\/[^>]+>/{lastline=NR}
         END{exit}')
  echo -n "$truncated" > "$2"
}

check_error_parameter() {
  if ! check_param_count_v2 "data file, XML parameter, expected value" 3 $#; then
    return 1
  fi
  if ! value=$(get_element_text "$1" "Error" "$2" 2>&1); then
    log 2 "error getting argument name: $value"
    return 1
  fi
  unescaped_value="$(xmlstarlet unesc "$value")"
  if [ "$unescaped_value" != "$3" ]; then
    log 2 "expected '$3', was '$unescaped_value'"
    return 1
  fi
  return 0
}

compare_data_with_xml_file() {
  if ! check_param_count_v2 "input file, expected data string" 2 $#; then
    return 1
  fi
  if ! output_file=$(get_file_name 2>&1); then
    log 2 "error getting output file file name: $output_file"
    return 1
  fi
  if ! expected_data=$(get_file_name 2>&1); then
    log 2 "error getting expected data file name: $expected_data"
    return 1
  fi
  if ! get_xml_data "$1" "$TEST_FILE_FOLDER/$output_file"; then
    log 2 "error getting xml data"
    return 1
  fi
  echo -en "$2" > "$TEST_FILE_FOLDER/$expected_data"
  if ! diff "$TEST_FILE_FOLDER/$expected_data" "$TEST_FILE_FOLDER/$output_file"; then
    return 1
  fi
  return 0
}
