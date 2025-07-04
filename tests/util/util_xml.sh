#!/usr/bin/env bash

build_xpath_string() {
  if ! check_param_count_gt "XML tree" 1 $#; then
    return 1
  fi
  xpath='//'
  for tree_val in "$@"; do
    xpath+='*[local-name()="'$tree_val'"]/'
  done
  xpath+='text()'
}

check_for_empty_element() {
  if ! check_param_count_gt "data file, XML tree" 2 $#; then
    return 1
  fi

  # shellcheck disable=SC2068
  if ! build_xpath_string ${@:2}; then
    log 2 "error building XPath search string"
    return 1
  fi
  if grep '<[^/][^ >]*>' "$1" | xmllint --xpath "'${xpath}[not(normalize-space())]'" -; then
    return 0
  fi
  return 1
}

get_element_text() {
  if [ $# -lt 2 ]; then
    log 2 "'get_element_text' requires data file, XML tree"
    return 1
  fi

  if ! build_xpath_string "${@:2}"; then
    log 2 "error building XPath search string"
    return 1
  fi

  log 5 "data: $(cat "$1")"
  if ! xml_val=$(grep '<[^/][^ >]*>' "$1" | xmllint --xpath "$xpath" - 2>&1); then
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

get_xml_data() {
  if ! check_param_count_v2 "data file, output file" 2 $#; then
    return 1
  fi
  log 5 "data: $(cat "$1")"

  # Find first line with "<?xml" and everything from there onward
  xml_start=$(grep -n "<?xml" "$1" | head -n 1 | cut -d: -f1)

  if [ -z "$xml_start" ]; then
    log 2 "No XML declaration found."
    return 1
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
