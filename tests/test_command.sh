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

# tags: unit
@test "run parallel - appends status to file and stdout" {
  local runner_log="$BATS_TEST_TMPDIR/runner log.txt" contents
  printf '%s\n' "existing entry" > "$runner_log"

  run bash -c '
    docker() {
      if [ "$1" == "image" ]; then return 0; fi
      printf "%s\n" "suite output"
      return 7
    }
    export -f docker
    bash ./tests/run_parallel.sh --log-folder "$1" --max-parallel-jobs 1 --log-file "$2" fake-image failing-suite
  ' bash "$BATS_TEST_TMPDIR" "$runner_log"

  assert_failure 1
  assert_output -p "started (pid:"
  assert_output -p "finished with status '7'"
  assert_output -p "log file:"
  assert_output -p "duration:"
  contents=$(<"$runner_log")
  assert_equal "$contents" "$(printf 'existing entry\n%s' "$output")"
}

# tags: unit
@test "run parallel - log-file requires a path" {
  run ./tests/run_parallel.sh --log-file

  assert_failure 1
  assert_output -p "--log-file requires a file path"
}

# tags: unit
@test "run parallel - resolves relative reports under log-folder in either option order" {
  local order folder contents

  for order in before after; do
    folder="$BATS_TEST_TMPDIR/$order/new logs"
    run bash -c '
      docker() { return 0; }
      export -f docker
      if [ "$1" == "before" ]; then
        options=(--log-folder "$2" --log-file parallel.log --html-report index.html)
      else
        options=(--log-file parallel.log --html-report index.html --log-folder "$2")
      fi
      bash ./tests/run_parallel.sh "${options[@]}" fake-image suite
    ' bash "$order" "$folder"

    assert_success
    assert [ -f "$folder/parallel.log" ]
    assert [ -f "$folder/index.html" ]
    contents=$(<"$folder/parallel.log")
    assert_equal "$contents" "$output"
    contents=$(<"$folder/index.html")
    [[ "$contents" == *'href="suite-'* ]]
    [[ "$contents" == *"</ul></body></html>" ]]
  done
}

# tags: unit
@test "run parallel - log-folder requires a path and help shows default" {
  local path

  run ./tests/run_parallel.sh --log-folder
  assert_failure 1
  assert_output "--log-folder requires a directory path"

  for path in "" --build-mode; do
    run ./tests/run_parallel.sh --log-folder "$path" fake-image suite
    assert_failure 1
    assert_output "--log-folder requires a directory path"
  done

  run ./tests/run_parallel.sh --help
  assert_success
  assert_output -p "--log-folder <path> Directory for suite logs (default: $PWD/runtime/log)."
}

# tags: unit
@test "run parallel - validates build-mode" {
  local mode

  run ./tests/run_parallel.sh --build-mode
  assert_failure 1
  assert_output "--build-mode requires rebuild, build-if-missing, or use-tag"

  for mode in "" invalid --log-file; do
    run ./tests/run_parallel.sh --build-mode "$mode" fake-image suite
    assert_failure 1
    assert_output "--build-mode requires rebuild, build-if-missing, or use-tag"
  done
}

# tags: unit
@test "run parallel - config-folder requires a path and help shows default" {
  local path

  run ./tests/run_parallel.sh --config-folder
  assert_failure 1
  assert_output "--config-folder requires a directory path"

  for path in "" --build-mode; do
    run ./tests/run_parallel.sh --config-folder "$path" fake-image suite
    assert_failure 1
    assert_output "--config-folder requires a directory path"
  done

  run ./tests/run_parallel.sh --help
  assert_success
  assert_output -p "--config-folder <path> Host configuration directory (default: $PWD/runtime/config)."
}

# tags: unit
@test "run parallel - mounts the default or custom host config folder" {
  local mode expected trace="$BATS_TEST_TMPDIR/docker-mounts"

  for mode in default custom; do
    expected="$PWD/runtime/config"
    if [ "$mode" == "custom" ]; then expected="$BATS_TEST_TMPDIR/custom config"; fi
    mkdir -p "$expected"
    expected="$(cd "$expected" && pwd -P)"
    run bash -c '
      trace="$1"
      docker() {
        if [ "$1" == "image" ]; then return 0; fi
        printf "%s\n" "$@" > "$trace"
      }
      export -f docker
      export trace
      options=()
      if [ "$3" == "custom" ]; then options=(--config-folder "$4"); fi
      bash ./tests/run_parallel.sh "${options[@]}" --log-folder "$2" fake-image suite
    ' bash "$trace" "$BATS_TEST_TMPDIR" "$mode" "$expected"

    assert_success
    run command grep -Fx -- "$expected:/home/tester/config" "$trace"
    assert_success
  done
}

# tags: unit
@test "run parallel - normalizes host mounts and HOST_LOG_FOLDER" {
  local root trace="$BATS_TEST_TMPDIR/docker-paths"
  root="$(cd "$BATS_TEST_TMPDIR" && pwd -P)"
  ln -s "$PWD/tests" "$root/tests"
  mkdir -p "$root/actual config"
  ln -s "$root/actual config" "$root/config link"

  run bash -c '
    trace="$1/docker-paths"
    docker() {
      if [ "$1" == "image" ]; then return 0; fi
      printf "%s\n" "$@" > "$trace"
    }
    export -f docker
    export trace
    cd "$1"
    bash ./tests/run_parallel.sh --config-folder "./config link" \
      --log-folder "./new logs" --log-file runner.log fake-image suite
  ' bash "$root"

  assert_success
  run command grep -Fx -- "$root/actual config:/home/tester/config" "$trace"
  assert_success
  run command grep -Fx -- "$root/new logs:/home/tester/log" "$trace"
  assert_success
  run command grep -Fx -- "HOST_LOG_FOLDER=$root/new logs" "$trace"
  assert_success
  assert [ -s "$root/new logs/runner.log" ]
}

# tags: unit
@test "run parallel - build modes select the expected Docker operations" {
  local scenario mode inspect_status expected trace="$BATS_TEST_TMPDIR/docker-calls"

  for scenario in "rebuild 0" "rebuild 1" "build-if-missing 0" "build-if-missing 1" "use-tag 0" "use-tag 1"; do
    read -r mode inspect_status <<< "$scenario"
    : > "$trace"
    run bash -c '
      trace="$1"
      inspect_status="$2"
      docker() {
        printf "%s\n" "$1" >> "$trace"
        if [ "$1" == "image" ]; then return "$inspect_status"; fi
        return 0
      }
      export -f docker
      export trace inspect_status
      bash ./tests/run_parallel.sh --log-folder "$3" --build-mode "$4" fake-image suite
    ' bash "$trace" "$inspect_status" "$BATS_TEST_TMPDIR" "$mode"

    if [ "$mode:$inspect_status" == "use-tag:1" ]; then
      assert_failure 1
    else
      assert_success
    fi
    case "$mode:$inspect_status" in
      rebuild:*) expected=$'build\nrun' ;;
      build-if-missing:1) expected=$'image\nbuild\nrun' ;;
      use-tag:1) expected="image" ;;
      *) expected=$'image\nrun' ;;
    esac
    assert_equal "$(<"$trace")" "$expected"
  done
}

# tags: unit
@test "run parallel - max-parallel-jobs requires a positive integer" {
  local count

  run ./tests/run_parallel.sh --max-parallel-jobs
  assert_failure 1
  assert_output "--max-parallel-jobs requires a positive integer"

  for count in "" 0 -1 1.5 invalid --build-mode; do
    run ./tests/run_parallel.sh --max-parallel-jobs "$count" fake-image failing-suite
    assert_failure 1
    assert_output "--max-parallel-jobs requires a positive integer"
  done
}

# tags: unit
@test "run parallel - lists available suites" {
  local expected

  run ./tests/run.sh -l
  assert_success
  expected="$output"

  run ./tests/run_parallel.sh -l
  assert_success
  assert_output "$expected"

  run ./tests/run_parallel.sh --list
  assert_success
  assert_output "$expected"
}

# tags: unit
@test "run parallel - requires two positional arguments after options" {
  run ./tests/run_parallel.sh --build-mode use-tag
  assert_failure 1
  assert_output -p "expected image tag and test suites after options"

  run ./tests/run_parallel.sh --build-mode use-tag fake-image
  assert_failure 1
  assert_output -p "expected image tag and test suites after options"

  run ./tests/run_parallel.sh fake-image suite --max-parallel-jobs 2
  assert_failure 1
  assert_output -p "expected image tag and test suites after options"
}

# tags: unit
@test "run parallel - HTML report escapes messages and links every suite log" {
  local report="$BATS_TEST_TMPDIR/reports/index.html" contents
  mkdir -p "$BATS_TEST_TMPDIR/reports"
  report="$(cd "$BATS_TEST_TMPDIR/reports" && pwd -P)/index.html"

  run bash -c '
    docker() {
      if [ "$1" == "image" ]; then return 0; fi
      for arg in "$@"; do if [ "$arg" == "-t" ]; then return 99; fi; done
      printf "%s\n" "suite output"
      if [ "${!#}" == "failing-suite" ]; then return 7; fi
    }
    export -f docker
    bash ./tests/run_parallel.sh --log-folder "$1/suite logs" --max-parallel-jobs 1 --html-report "$2" fake-image "pass&<suite>,failing-suite"
  ' bash "$BATS_TEST_TMPDIR" "$report"

  assert_failure 1
  assert_output -p "HTML report: $report"
  contents=$(<"$report")
  [[ "$contents" == *"pass&amp;&lt;suite&gt;"* ]]
  [[ "$contents" != *"pass&<suite>"* ]]
  [[ "$contents" == *"finished with status &#39;0&#39;"* ]]
  [[ "$contents" == *"finished with status &#39;7&#39;"* ]]
  [[ "$contents" == *'href="../suite%20logs/pass%26%3Csuite%3E-'* ]]
  [[ "$contents" == *'href="../suite%20logs/failing-suite-'* ]]
  [[ "$contents" == *"duration:"* ]]
  [[ "$contents" == *"</ul></body></html>" ]]
}

# tags: unit
@test "run parallel - html-report requires a path" {
  run ./tests/run_parallel.sh --html-report

  assert_failure 1
  assert_output -p "--html-report requires a file path"
}

# tags: unit
@test "run parallel - rejects all combined with other suites" {
  local suites

  for suites in s3,all all,s3 s3,all,rest; do
    run ./tests/run_parallel.sh --build-mode rebuild fake-image "$suites"
    assert_failure 1
    assert_output "all must be used alone, not combined with other suites"
  done
}

# tags: unit
@test "run parallel - stops before Docker when suite discovery fails or is empty" {
  local mode marker="$BATS_TEST_TMPDIR/docker-called"

  for mode in failed empty; do
    run bash -c '
      mode="$1"
      marker="$2"
      function ./tests/run.sh {
        if [ "$mode" == "failed" ]; then return 7; fi
        printf "   \n"
      }
      docker() { touch "$marker"; }
      set -- --build-mode rebuild fake-image all
      source ./tests/run_parallel.sh
    ' bash "$mode" "$marker"

    assert_failure 1
    if [ "$mode" == "failed" ]; then
      assert_output "unable to list test suites"
    else
      assert_output "no test suites found"
    fi
    assert [ ! -e "$marker" ]
  done
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

  PATH="$fake_bin:$PATH" run ./tests/run_parallel.sh --log-folder "$log_folder" --max-parallel-jobs 1 --build-mode use-tag "fake-image" "failing-suite"

  assert_failure
  assert_output -p "finished with status '7'"
  assert_output -p "log file:  $log_folder/failing-suite-"
  matching_logs=("$log_folder"/failing-suite-*.log)
  assert [ -f "${matching_logs[0]}" ]
}
