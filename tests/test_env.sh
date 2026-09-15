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
@test "teardown command log - appends to existing test log" {
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
  [[ "$contents" == *"existing test log"* ]]
  [[ "$contents" == *"command log entry"* ]]
  [[ "$contents" == *"**********************************************************************************"* ]]
}

# tags: unit
@test "teardown command log - prints when test log is missing and test fails" {
  TEST_ID="command-log-missing-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  COMMAND_LOG="$TEST_FILE_FOLDER/command-$(uuidgen).log"
  BATS_TEST_COMPLETED=0
  printf '%s\n' "failed command log entry" > "$COMMAND_LOG"

  run teardown_command_log

  assert_success
  assert_output -p "failed command log entry"
  assert_output -p "**********************************************************************************"
  assert [ ! -f "$COMMAND_LOG" ]
  assert [ ! -f "${TEST_LOG_FILE}.${TEST_ID}" ]
}

# tags: unit
@test "teardown command log - deletes only when test log is missing and test passes" {
  TEST_ID="command-log-complete-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  COMMAND_LOG="$TEST_FILE_FOLDER/command-$(uuidgen).log"
  BATS_TEST_COMPLETED=1
  printf '%s\n' "completed command log entry" > "$COMMAND_LOG"

  run teardown_command_log

  assert_success
  assert_output ""
  assert [ ! -f "$COMMAND_LOG" ]
  assert [ ! -f "${TEST_LOG_FILE}.${TEST_ID}" ]
}

# tags: unit
@test "teardown command log - fails when delete fails" {
  local fake_bin

  fake_bin="$TEST_FILE_FOLDER/bin-$(uuidgen)"
  TEST_ID="command-log-delete-fail-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  COMMAND_LOG="$TEST_FILE_FOLDER/command-$(uuidgen).log"
  mkdir -p "$fake_bin"
  printf '%s\n' "command log entry" > "$COMMAND_LOG"
  cat > "$fake_bin/rm" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "fake rm failure" >&2
exit 1
EOF
  chmod +x "$fake_bin/rm"

  PATH="$fake_bin:$PATH" run teardown_command_log

  assert_failure 1
  assert_output -p "error deleting command log"
  assert [ -f "$COMMAND_LOG" ]
}

# tags: unit
@test "teardown versity log - appends to existing test log" {
  local test_log versity_log contents

  TEST_ID="versity-log-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  VERSITY_LOG_FILE="$TEST_FILE_FOLDER/versity-$(uuidgen).log"
  test_log="${TEST_LOG_FILE}.${TEST_ID}"
  versity_log="${VERSITY_LOG_FILE}.${TEST_ID}.1"
  printf '%s\n' "existing test log" > "$test_log"
  printf '%s\n' "versity log entry" > "$versity_log"

  run teardown_versity_log 1 "$versity_log"

  assert_success
  assert_output ""
  assert [ ! -f "$versity_log" ]
  contents=$(<"$test_log")
  [[ "$contents" == *"existing test log"* ]]
  [[ "$contents" == *"versity log entry"* ]]
  [[ "$contents" == *"**********************************************************************************"* ]]
}

# tags: unit
@test "teardown versity log - prints when test log is missing and test fails" {
  local versity_log

  TEST_ID="versity-log-missing-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  VERSITY_LOG_FILE="$TEST_FILE_FOLDER/versity-$(uuidgen).log"
  BATS_TEST_COMPLETED=0
  versity_log="${VERSITY_LOG_FILE}.${TEST_ID}.1"
  printf '%s\n' "failed versity log entry" > "$versity_log"

  run teardown_versity_log 1 "$versity_log"

  assert_success
  assert_output -p "failed versity log entry"
  assert_output -p "**********************************************************************************"
  assert [ ! -f "$versity_log" ]
  assert [ ! -f "${TEST_LOG_FILE}.${TEST_ID}" ]
}

# tags: unit
@test "teardown versity log - fails when delete fails" {
  local fake_bin test_log versity_log contents

  fake_bin="$TEST_FILE_FOLDER/bin-$(uuidgen)"
  TEST_ID="versity-log-delete-fail-$(uuidgen)"
  TEST_LOG_FILE="$TEST_FILE_FOLDER/test-$(uuidgen).log"
  VERSITY_LOG_FILE="$TEST_FILE_FOLDER/versity-$(uuidgen).log"
  test_log="${TEST_LOG_FILE}.${TEST_ID}"
  versity_log="${VERSITY_LOG_FILE}.${TEST_ID}.1"
  mkdir -p "$fake_bin"
  printf '%s\n' "existing test log" > "$test_log"
  printf '%s\n' "versity log entry" > "$versity_log"
  cat > "$fake_bin/rm" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "fake rm failure" >&2
exit 1
EOF
  chmod +x "$fake_bin/rm"

  PATH="$fake_bin:$PATH" run teardown_versity_log 1 "$versity_log"

  assert_failure 1
  assert_output ""
  assert [ -f "$versity_log" ]
  contents=$(<"$test_log")
  [[ "$contents" == *"error deleting log file"* ]]
  [[ "$contents" == *"fake rm failure"* ]]
}
