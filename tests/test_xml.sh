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

# tags: unit
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
  assert_output -p 'element has no name'

  run build_xpath_string_for_element "XML With Space"
  assert_failure
  assert_output -p "element 'XML With Space' contains a space"
}

# tags: unit
@test "get_xml_data - missing params" {
  run get_xml_data "oneparam"
  assert_failure
  assert_output -p "requires data file, output file"
}

# tags: unit
@test "get_xml_data - file doesn't exist" {
  run get_xml_data "/nonexistent_$$" "/tmp/out"
  assert_failure
  assert_output -p "does not exist"
}

# tags: unit
@test "get_xml_data - no XML content" {
  input=$(get_file_name)
  printf 'HTTP/1.1 500\r\n\r\nNo XML here' > "$TEST_FILE_FOLDER/$input"
  run get_xml_data "$TEST_FILE_FOLDER/$input" "dontcare"
  assert_failure
  assert_output -p "No XML declaration found"
}

# tags: unit
@test "get_xml_data - valid XML with declaration" {
  input=$(get_file_name)
  printf 'HTTP/1.1 200\r\n\r\n<?xml version="1.0"?><Value>OK</Value>' > "$TEST_FILE_FOLDER/$input"
  run compare_data_with_xml_file "$TEST_FILE_FOLDER/$input" "<?xml version=\"1.0\"?>\n<Value>OK</Value>"
  assert_success
}

# tags: unit
@test "get_xml_data - valid XML without declaration" {
  input=$(get_file_name)
  printf 'HTTP/1.1 200\r\n\r\n<Value>AlsoOK</Value>' > "$TEST_FILE_FOLDER/$input"
  run compare_data_with_xml_file "$TEST_FILE_FOLDER/$input" "<?xml version=\"1.0\"?>\n<Value>AlsoOK</Value>"
  assert_success
}

# tags: unit
@test "get_xml_data - XML with extra content after root" {
  input=$(get_file_name)
  printf 'HTTP/1.1 200\r\n\r\n<Value>AgainOK</Value>extra' > "$TEST_FILE_FOLDER/$input"
  run compare_data_with_xml_file "$TEST_FILE_FOLDER/$input" "<?xml version=\"1.0\"?>\n<Value>AgainOK</Value>"
  assert_success
}

@test "check_for_empty_or_nonexistent_element" {
  run get_file_names 6
  assert_success
  read -r file_one file_two file_three file_four file_five <<< "$output"

  printf '<Outer><Inner></Inner></Outer>' > "$TEST_FILE_FOLDER/$file_one"
  printf '<Outer><Inner/></Outer>' > "$TEST_FILE_FOLDER/$file_two"
  printf '<Outer><Inner>a</Inner></Outer>' > "$TEST_FILE_FOLDER/$file_three"
  printf '<Outer></Outer>' > "$TEST_FILE_FOLDER/$file_four"
  printf '<Invalid XML><Inner></Inner></Invalid XML>' > "$TEST_FILE_FOLDER/$file_five"

  run check_for_empty_or_nonexistent_element "$TEST_FILE_FOLDER/$file_one" "Outer" "Inner"
  assert_success

  run check_for_empty_or_nonexistent_element "$TEST_FILE_FOLDER/$file_two" "Outer" "Inner"
  assert_success

  run check_for_empty_or_nonexistent_element "$TEST_FILE_FOLDER/$file_three" "Outer" "Inner"
  assert_failure 1

  run check_for_empty_or_nonexistent_element "$TEST_FILE_FOLDER/$file_four" "Outer" "Inner"
  assert_success

  run check_for_empty_or_nonexistent_element "$TEST_FILE_FOLDER/$file_five" "Invalid XML" "Inner"
  assert_failure 2
}

@test "get_element_text_inside_string" {
  local string_one='<Outer><Inner>text</Inner></Outer>'
  local string_two='<Outer><Inner></Inner></Outer>'
  local string_three='<Outer><Inner/></Outer>'
  local string_four='<Outer></Outer>'

  run get_element_text_inside_string "$string_one" "Inner"
  assert_success
  assert_output "text"

  run get_element_text_inside_string "$string_two" "Inner"
  assert_success
  assert_output ""

  run get_element_text_inside_string "$string_three" "Inner"
  assert_success
  assert_output ""

  run get_element_text_inside_string "$string_four" "Inner"
  assert_failure
  assert_output -p "element matching"
}

@test "check_xml_element" {
  run get_file_names 4
  assert_success
  read -r file_one file_two file_three file_four <<< "$output"

  printf '<Outer><Inner>text</Inner></Outer>' > "$TEST_FILE_FOLDER/$file_one"
  printf '<Outer><Inner/></Outer>' > "$TEST_FILE_FOLDER/$file_two"
  printf '<Outer><Inner></Inner></Outer>' > "$TEST_FILE_FOLDER/$file_three"
  printf '<Outer></Outer>' > "$TEST_FILE_FOLDER/$file_four"

  run check_xml_element "$TEST_FILE_FOLDER/$file_one" "tex" "Outer" "Inner"
  assert_failure
  assert_output -p "expected 'tex', actual 'text'"

  run check_xml_element "$TEST_FILE_FOLDER/$file_one" "text" "Outer" "Inner"
  assert_success

  run check_xml_element "$TEST_FILE_FOLDER/$file_two" "a" "Outer" "Inner"
  assert_failure
  assert_output -p "expected 'a', actual ''"

  run check_xml_element "$TEST_FILE_FOLDER/$file_two" "" "Outer" "Inner"
  assert_success

  run check_xml_element "$TEST_FILE_FOLDER/$file_three" "" "Outer" "Inner"
  assert_success

  run check_xml_element "$TEST_FILE_FOLDER/$file_four" "" "Outer" "Inner"
  assert_failure
  assert_output -p "element matching"
}
