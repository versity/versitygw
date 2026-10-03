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

source ./tests/logger.sh
source ./tests/drivers/params.sh
source ./tests/env.sh
source ./tests/setup_unit.sh

# tags: unit
@test "teardown time log - elapsed time written" {
  local duration log_line

  TIME_LOG="$TEST_FILE_FOLDER/time-$(uuidgen).log"
  BATS_TEST_NAME="time log test"
  START_TIME=$(date +%s)

  run teardown_time_log

  assert_success
  assert [ -f "$TIME_LOG" ]
  log_line=$(<"$TIME_LOG")
  duration=${log_line#"time log test: "}
  duration=${duration%"s"}
  assert [ "$log_line" != "$duration" ]
  assert [ "$duration" -ge 0 ]
  assert [ "$duration" -le 2 ]
}

# tags: unit
@test "teardown time log - succeeds without TIME_LOG" {
  unset TIME_LOG
  BATS_TEST_NAME="time log unset test"
  START_TIME=$(date +%s)

  run teardown_time_log

  assert_success
  assert_output ""
}

# tags: unit
@test "teardown appended log - appends to existing test log" {
  local test_log appended_log contents

  TEST_ID="appended-log-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  appended_log="$TEST_FILE_FOLDER/appended-$(uuidgen).log"
  test_log="${TEST_LOG_FILE}.${TEST_ID}"
  printf '%s\n' "existing test log" > "$test_log"
  printf '%s\n' "appended log entry" > "$appended_log"

  run teardown_appended_log "$appended_log"

  assert_success
  assert_output ""
  assert [ ! -f "$appended_log" ]
  contents=$(<"$test_log")
  [[ "$contents" == *"existing test log"* ]]
  [[ "$contents" == *"appended log entry"* ]]
  [[ "$contents" == *"**********************************************************************************"* ]]
}

# tags: unit
@test "teardown appended log - prints when test log is missing and test fails" {
  local appended_log

  TEST_ID="appended-log-missing-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  BATS_TEST_COMPLETED=0
  appended_log="$TEST_FILE_FOLDER/appended-$(uuidgen).log"
  printf '%s\n' "failed appended log entry" > "$appended_log"

  run teardown_appended_log "$appended_log"

  assert_success
  assert_output -p "failed appended log entry"
  assert_output -p "**********************************************************************************"
  assert [ ! -f "$appended_log" ]
  assert [ ! -f "${TEST_LOG_FILE}.${TEST_ID}" ]
}

# tags: unit
@test "teardown appended log - deletes only when test log is missing and test passes" {
  local appended_log

  TEST_ID="appended-log-complete-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  BATS_TEST_COMPLETED=1
  appended_log="$TEST_FILE_FOLDER/appended-$(uuidgen).log"
  printf '%s\n' "completed appended log entry" > "$appended_log"

  run teardown_appended_log "$appended_log"

  assert_success
  assert_output ""
  assert [ ! -f "$appended_log" ]
  assert [ ! -f "${TEST_LOG_FILE}.${TEST_ID}" ]
}

# tags: unit
@test "teardown appended log - fails when delete fails" {
  local fake_bin test_log appended_log contents

  fake_bin="$TEST_FILE_FOLDER/bin-$(uuidgen)"
  TEST_ID="appended-log-delete-fail-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  test_log="${TEST_LOG_FILE}.${TEST_ID}"
  appended_log="$TEST_FILE_FOLDER/appended-$(uuidgen).log"
  mkdir -p "$fake_bin"
  printf '%s\n' "existing test log" > "$test_log"
  printf '%s\n' "appended log entry" > "$appended_log"
  cat > "$fake_bin/rm" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "fake rm failure" >&2
exit 1
EOF
  chmod +x "$fake_bin/rm"

  PATH="$fake_bin:$PATH" run teardown_appended_log "$appended_log"

  assert_failure 1
  assert_output ""
  assert [ -f "$appended_log" ]
  contents=$(<"$test_log")
  [[ "$contents" == *"error deleting log file"* ]]
  [[ "$contents" == *"fake rm failure"* ]]
}

# tags: unit
@test "teardown command log - uses COMMAND_LOG" {
  local test_log contents

  TEST_ID="command-log-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  COMMAND_LOG="$TEST_FILE_FOLDER/command-$(uuidgen).log"
  test_log="${TEST_LOG_FILE}.${TEST_ID}"
  printf '%s\n' "existing test log" > "$test_log"
  printf '%s\n' "command log entry" > "$COMMAND_LOG"

  run teardown_command_log

  assert_success
  assert_output ""
  assert [ ! -f "$COMMAND_LOG" ]
  contents=$(<"$test_log")
  [[ "$contents" == *"command log entry"* ]]
}

# tags: unit
@test "main log cleanup - fails when appending temp log fails" {
  local main_log temp_log

  TEST_ID="main-log-append-fail-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/main-log-$(uuidgen)"
  BATS_TEST_COMPLETED=0
  main_log="$TEST_LOG_FILE"
  temp_log="${TEST_LOG_FILE}.${TEST_ID}"
  mkdir -p "$main_log"
  printf '%s\n' "temp test log entry" > "$temp_log"

  run main_log_cleanup

  TEST_LOG_FILE=

  assert_failure 1
  assert_output -p "error appending temp log to main log"
  assert [ -d "$main_log" ]
  assert [ -f "$temp_log" ]
}

# tags: unit
@test "main log cleanup - skips append when LOG_ON_SUCCESS is false" {
  local main_log temp_log contents

  TEST_ID="main-log-success-skip-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/main-log-$(uuidgen).log"
  BATS_TEST_COMPLETED=1
  LOG_ON_SUCCESS=false
  main_log="$TEST_LOG_FILE"
  temp_log="${TEST_LOG_FILE}.${TEST_ID}"
  printf '%s\n' "existing main log" > "$main_log"
  printf '%s\n' "successful temp log entry" > "$temp_log"

  run main_log_cleanup

  assert_success
  assert_output ""
  assert [ ! -f "$temp_log" ]
  contents=$(<"$main_log")
  [[ "$contents" == *"existing main log"* ]]
  [[ "$contents" != *"successful temp log entry"* ]]
}

# tags: unit
@test "teardown versity log - uses provided log name" {
  local test_log versity_log contents

  TEST_ID="versity-log-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  test_log="${TEST_LOG_FILE}.${TEST_ID}"
  versity_log="$TEST_FILE_FOLDER/versity-$(uuidgen).log"
  printf '%s\n' "existing test log" > "$test_log"
  printf '%s\n' "versity log entry" > "$versity_log"

  run teardown_versity_log "$versity_log"

  assert_success
  assert_output ""
  assert [ ! -f "$versity_log" ]
  contents=$(<"$test_log")
  [[ "$contents" == *"versity log entry"* ]]
}
