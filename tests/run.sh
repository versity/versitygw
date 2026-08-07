#!/usr/bin/env bash

# Copyright 2024 Versity Software
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

source ./tests/drivers/params.sh

show_help() {
  echo "Usage: $0 [option...]"
  echo "   -h, --help                             Display this help message and exit"
  echo "   -l                                     Only list suites (don't run)"
  echo "   env BATS=<path>                        Use a specific bats executable path"
  echo "   env VERSITYGW_TEST_ENV=<path>          env file to pass to tests"
  echo "all                                       Attempt to run all tests (not recommended here due to time, use run_parallel.sh to run in parallel)"
  echo "{suite} {pattern}                         Attempt to run tests matching pattern in single suite"
  echo "                                          Suites below (to run multiple, separate by comma)"
  echo_help_lines
}

get_bats_executable() {
  if [ -n "$BATS" ]; then
    if [ ! -x "$BATS" ]; then
      echo "BATS executable '$BATS' not found or not executable" >&2
      return 1
    fi
    printf '%s\n' "$BATS"
    return 0
  fi
  if bats_cmd="$(command -v bats 2>/dev/null)" && [[ -x "$bats_cmd" ]]; then
    printf '%s\n' "$bats_cmd"
    return 0
  fi
  echo "unable to find bats executable; set BATS=<path>" >&2
  return 1
}

echo_help_lines() {
  local run_sets_list run_sets=() run_set description spaces_needed

  run_sets_list=$(get_run_sets_and_files_if_needed)
  read -r -a run_sets <<< "$run_sets_list"

  for run_set in "${run_sets[@]}"; do
    description=${run_set/-/ }
    if [[ "$description" == *"rest"* ]]; then
      description=${description/rest/REST}
    fi
    spaces_needed=$((42-${#run_set}))
    printf "%s%-${spaces_needed}s%s\n" "$run_set" "" "Run $description tests"
  done
}

get_run_sets_and_files_if_needed() {
  if ! check_param_count_le "'true', if files desired" 1 $#; then
    return 1
  fi
  local want_files="$1"

  if [ -n "$want_files" ] && [ "$want_files" != "true" ]; then
    echo "param for printing files as well must be 'true' or unset"
    return 1
  fi

  local f files=() file_without_header file_without_sh run_set run_sets=()

  while IFS= read -r f; do
    if grep -q '@test' "$f"; then
      if [ "$want_files" == "true" ]; then
        files+=("$f")
      fi
      file_without_header=${f/tests\/test_/}
      file_without_sh=${file_without_header/.sh/}
      run_set=${file_without_sh//_/-}
      run_sets+=("$run_set")
    fi
  done < <(find tests -name 'test_*.sh' | sort)
  printf '%s\n' "${run_sets[*]}"
  if [ "$want_files" == "true" ]; then
    printf '%s\n' "${files[*]}"
  fi
}

# return 0 for complete, 1 for continue checking suites, 2 for error
run_set_if_matching() {
  if ! check_param_count_gt "desired run set, current run set name, current file name, test pattern (optional)" 3 $#; then
    return 2
  fi
  local desired_run_set="$1" current_run_set="$2" current_file="$3" test_pattern="$4" bats_executable

  if ! bats_executable=$(get_bats_executable); then
    return 2
  fi

  if [ "$desired_run_set" == "all" ]; then
    echo "running '$current_run_set' test suite ..."
    if ! "$bats_executable" "$current_file"; then
      echo "error running '$current_run_set' tests" >&2
      return 2
    fi
    return 1
  elif [ "$current_run_set" == "$desired_run_set" ]; then
    if [ "$test_pattern" != "" ]; then
      echo "running test(s) matching '$test_pattern' in '$current_run_set' test suite ..."
      if ! "$bats_executable" "$current_file" "-f" "$test_pattern"; then
        echo "error running '$test_pattern' test(s) in '$current_run_set' suite" >&2
        return 2
      fi
    else
      echo "running '$current_run_set' test suite ..."
      if ! "$bats_executable" "$current_file"; then
        echo "error running '$current_run_set' suite" >&2
        return 2
      fi
    fi
    return 0
  fi
  return 1
}

handle_tags() {
  if [ "$#" -eq 0 ]; then
    ./tests/tags/get_tests.sh "-h"
    echo "To run from run.sh, replace 'get_tests.sh' path with '--tags'"
    return 1
  fi
  ./tests/tags/get_tests.sh "$@"
}

handle_param() {
  if ! check_param_count_ge_le "run set, test pattern (optional)" 1 2 $#; then
    return 1
  fi
  local run_set="$1" test_pattern="$2"
  local run_sets_and_files lines run_sets files idx run_result

  run_sets_and_files=$(get_run_sets_and_files_if_needed "true")
  mapfile -t lines <<< "$run_sets_and_files"
  read -r -a run_sets <<< "${lines[0]}"
  read -r -a files <<< "${lines[1]}"

  for idx in "${!run_sets[@]}"; do
    run_result=0
    run_set_if_matching "$run_set" "${run_sets[$idx]}" "${files[$idx]}" "$test_pattern" || run_result=$?
    if [ "$run_result" -eq 0 ]; then
      break
    elif [ "$run_result" -eq 2 ]; then
      echo "error running set '$run_set" >&2
      return 1
    fi
  done

  if [ "$run_result" -eq 1 ] && [ "$run_set" != "all" ]; then
    echo "no suites matching '$run_set'" > /dev/stderr
    return 1
  fi
  return 0
}

list_all_test_suites() {
  local run_set_list run_sets set_length last_idx matching_test_string=""

  run_set_list=$(get_run_sets_and_files_if_needed)
  read -r -a run_sets <<< "$run_set_list"
  set_length=${#run_sets[@]}

  if [ "$set_length" -le 0 ]; then
    printf '\n'
    return 0
  fi

  last_idx=$((set_length-1))
  for idx in "${!run_sets[@]}"; do
    matching_test_string+="${run_sets[$idx]}"
    if [ "$idx" -lt "$last_idx" ]; then
      matching_test_string+=","
    fi
  done
  printf '%s\n' "$matching_test_string"
  return 0
}

if [ $# -le 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  show_help
  exit 0
fi

if [ "$1" == "--tags" ]; then
  if ! handle_tags "${@:2}"; then
    exit 1
  fi
  exit 0
fi

if [ "$1" == "-l" ]; then
  list_all_test_suites
  exit 0
fi

IFS=',' read -ra options <<< "$1"
if [ "$2" != "" ] && [ "${#options[@]}" -gt 1 ]; then
  echo "cannot call multiple suites with test name" >&2
  exit 1
fi
for option in "${options[@]}"; do
  if ! handle_param "$option" "$2"; then
    exit 1
  fi
done

# shellcheck disable=SC2086
exit 0
