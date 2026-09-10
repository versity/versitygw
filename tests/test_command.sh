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

# tags: unit
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

@test "Run parallel test, print log on failure" {
  local fake_bin log_folder matching_logs

  fake_bin="$TEST_FILE_FOLDER/bin"
  log_folder="$TEST_FILE_FOLDER/run_parallel_logs"
  mkdir -p "$fake_bin" "$log_folder"

  cat > "$fake_bin/docker" <<'EOF'
#!/usr/bin/env bash

if [ "$1" == "image" ] && [ "$2" == "inspect" ]; then
  exit 0
fi
if [ "$1" == "run" ]; then
  printf '%s\n' "fake test failure"
  exit 7
fi
printf 'unexpected docker args: %s\n' "$*" >&2
exit 1
EOF
  chmod +x "$fake_bin/docker"

  PATH="$fake_bin:$PATH" run ./tests/run_parallel.sh "fake-image" "failing-suite" 1 "$log_folder" --use-tag

  assert_success
  assert_output -p "finished with status '7'"
  assert_output -p "log file:  $log_folder/failing-suite-"
  matching_logs=("$log_folder"/failing-suite-*.log)
  assert [ -f "${matching_logs[0]}" ]
}
