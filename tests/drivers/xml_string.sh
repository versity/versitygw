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
  local response xpath

  if ! response=$(build_xpath_string_for_element "$@" 2>&1); then
    log 2 "error building xpath: $response"
    return 1
  fi
  xpath+='/text()'
  echo "$xpath"
  return 0
}

get_xpath_segment() {
  if ! check_param_count_gt "XML element name" 1 $#; then
    return 1
  fi
  if [ "$1" == "" ]; then
    log 2 "element has no name"
    return 1
  fi
  if [[ "$1" =~ [[:space:]] ]]; then
    log 2 "element '$1' contains a space"
    return 1
  fi
  echo '*[local-name()="'"$1"'"]'
}


build_xpath_string_for_element() {
  if ! check_param_count_gt "XML tree" 1 $#; then
    return 1
  fi
  local xpath='//'
  for ((idx=1;idx<=$#;idx++)); do
    if ! segment=$(get_xpath_segment "${!idx}" 2>&1); then
      log 2 "error getting xpath segment: $segment"
      return 1
    fi
    xpath+="$segment"
    if [ "$idx" != $# ]; then
      xpath+='/'
    fi
  done
  echo "$xpath"
  return 0
}

get_inner_xpath_string_for_element() {
  if ! check_param_count_gt "compare element, XML tree" 2 $#; then
    return 1
  fi
  local xpath='['
  for ((idx=2;idx<=$#;idx++)); do
    if ! xpath+=$(get_xpath_segment "${!idx}" 2>&1); then
      log 2 "error getting xpath segment: $xpath"
      return 1
    fi
    if [ "$idx" != $# ]; then
      xpath+='/'
    fi
  done
  xpath+="='$1']"
  echo "$xpath"
  return 0
}

check_xml_element_inside_string() {
  if ! check_param_count_gt "string, expected value, XML tree" 3 $#; then
    return 1
  fi
  local response xml_value

  if ! response=$(get_element_text_inside_string "$1" "${@:3}" 2>&1); then
    log 2 "error getting actual value: $response"
    return 1
  fi
  xml_value="$response"

  if [ "$xml_value" != "$2" ]; then
    log 2 "expected value '$2', was '$xml_value'"
    return 1
  fi
  return 0
}

get_elements_inside_string() {
  if ! check_param_count_gt "string, XML tree" 2 $#; then
    return 1
  fi

  local response xpath
  if ! response=$(build_xpath_string_for_element "${@:2}" 2>&1); then
    log 2 "error building XPath search string: $response"
    return 1
  fi
  xpath="$response"

  if ! response=$(xmllint --xpath "${xpath}" - <<< "$1" 2>&1); then
    if [[ "$response" == *"XPath set is empty"* ]]; then
      echo ""
      return 0
    fi
    log 2 "error getting element text: $response"
    return 1
  fi
  echo "$response"
  return 0
}

get_element_text_inside_string() {
  if ! check_param_count_gt "string, XML tree" 2 $#; then
    return 1
  fi
  local response xpath result

  if ! response=$(build_xpath_string_for_element "${@:2}" 2>&1); then
    log 2 "error building XPath search string: $response"
    return 1
  fi
  xpath="$response"

  result=$(xmllint --xpath "boolean($xpath)" - <<< "$1" 2>&1)
  if [ "$result" == "false" ]; then
    log 2 "element matching '$xpath' doesn't exist"
    return 1
  fi

  if ! response=$(xmllint --xpath "${xpath}/text()" - <<< "$1" 2>&1); then
    if [[ "$response" == *"XPath set is empty"* ]]; then
      echo ""
      return 0
    fi
    log 2 "error getting element text: $response"
    return 1
  fi
  echo "$response"
  return 0
}


