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

source ./tests/commands/command.sh
source ./tests/logger.sh
source ./tests/setup_unit.sh

@test "check_for_and_or_build_go_executable" {
  export GO_COMMAND_GENERATOR_EXECUTABLE=
  run check_for_and_or_build_go_executable
  assert_failure 1

  export GO_COMMAND_GENERATOR_EXECUTABLE="/dev/null/dummy"
  run check_for_and_or_build_go_executable
  assert_failure 1
  assert_output -p "error building generateCommand executable"

  command_executable="$TEST_FILE_FOLDER/$(uuidgen)"
  export GO_COMMAND_GENERATOR_EXECUTABLE="$command_executable"
  run check_for_and_or_build_go_executable
  assert_success
  assert [ -f "$command_executable" ]

  run check_for_and_or_build_go_executable
  assert_success
}
