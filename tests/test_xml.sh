#!/usr/bin/env bats

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

load ./bats-support/load
load ./bats-assert/load

source ./tests/drivers/file.sh
source ./tests/drivers/xml.sh
source ./tests/drivers/params.sh
source ./tests/logger.sh
source ./tests/setup_unit.sh

@test "build_xpath_string_for_element" {
  run build_xpath_string_for_element
  assert_failure
  assert_output -p "requires"

  run build_xpath_string_for_element "Error"
  assert_success
  assert_output '//*[local-name()="Error"]'

  run build_xpath_string_for_element "Error" "Code"
  assert_success
  assert_output '//*[local-name()="Error"]/*[local-name()="Code"]'

  run build_xpath_string_for_element "dontcare" ""
  assert_failure
  assert_output -p 'param number 2 is empty'

  run build_xpath_string_for_element "XML With Space"
  assert_failure
  assert_output -p "param 'XML With Space' contains a space"
}

@test "get_xml_data - missing params" {
  run get_xml_data "oneparam"
  assert_failure
  assert_output -p "requires data file, output file"
}

@test "get_xml_data - file doesn't exist" {
  run get_xml_data "/nonexistent_$$" "/tmp/out"
  assert_failure
  assert_output -p "does not exist"
}

@test "get_xml_data - no XML content" {
  input=$(get_file_name)
  printf 'HTTP/1.1 500\r\n\r\nNo XML here' > "$TEST_FILE_FOLDER/$input"
  run get_xml_data "$TEST_FILE_FOLDER/$input" "dontcare"
  assert_failure
  assert_output -p "No XML declaration found"
}

@test "get_xml_data - valid XML with declaration" {
  input=$(get_file_name)
  printf 'HTTP/1.1 200\r\n\r\n<?xml version="1.0"?><Value>OK</Value>' > "$TEST_FILE_FOLDER/$input"
  run compare_data_with_xml_file "$TEST_FILE_FOLDER/$input" "<?xml version=\"1.0\"?>\n<Value>OK</Value>"
  assert_success
}

@test "get_xml_data - valid XML without declaration" {
  input=$(get_file_name)
  printf 'HTTP/1.1 200\r\n\r\n<Value>AlsoOK</Value>' > "$TEST_FILE_FOLDER/$input"
  run compare_data_with_xml_file "$TEST_FILE_FOLDER/$input" "<?xml version=\"1.0\"?>\n<Value>AlsoOK</Value>"
  assert_success
}

@test "get_xml_data - XML with extra content after root" {
  input=$(get_file_name)
  printf 'HTTP/1.1 200\r\n\r\n<Value>AgainOK</Value>extra' > "$TEST_FILE_FOLDER/$input"
  run compare_data_with_xml_file "$TEST_FILE_FOLDER/$input" "<?xml version=\"1.0\"?>\n<Value>AgainOK</Value>"
  assert_success
}
