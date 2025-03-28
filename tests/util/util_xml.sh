#!/usr/bin/env bash

get_element_text() {
  if [ $# -lt 2 ]; then
    log 2 "'get_element_text' requires data source, XML tree"
    return 1
  fi
  local xpath='//'
  for tree_val in "${@:2}"; do
    xpath+='*[local-name()="'$tree_val'"]/'
  done
  xpath+='text()'
  if ! xml_val=$(xmllint --xpath "$xpath" "$1" 2>&1); then
    log 2 "error getting XML value matching $xpath: $xml_val (file data: $(cat "$1"))"
    return 1
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
  if ! xml_val=$(get_element_text "$1" "${@:3}"); then
    log 2 "error getting element text"
    return 1
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
