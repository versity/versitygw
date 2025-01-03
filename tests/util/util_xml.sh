#!/usr/bin/env bash

check_xml_element() {
  if [ $# -lt 3 ]; then
    log 2 "'check_xml_element' requires data source, expected value, XML tree"
    return 1
  fi
  local xpath='//'
  for tree_val in "${@:3}"; do
    xpath+='*[local-name()="'$tree_val'"]/'
  done
  xpath+='text()'
  if ! xml_val=$(xmllint --xpath "$xpath" "$1" 2>&1); then
    log 2 "error getting XML value matching $xpath: $xml_val"
    return 1
  fi
  if [ "$2" != "$xml_val" ]; then
    log 2 "XML data mismatch, expected '$2', actual '$xml_val'"
    return 1
  fi
  return 0
}