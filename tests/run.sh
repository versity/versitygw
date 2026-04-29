#!/bin/bash

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
  echo "                                          Separate the below by comma"
  echo "all                                       Attempt to run all tests (not recommended)"
  echo "{suite} {pattern}                         Attempt to run tests matching pattern in single suite"
  echo_help_lines
}

echo_help_lines() {
  gather_test_files

  for run_set in "${run_sets[@]}"; do
    description=${run_set/-/ }
    if [[ "$description" == *"rest"* ]]; then
      description=${description/rest/REST}
    fi
    spaces_needed=$((42-${#run_set}))
    printf "%s%-${spaces_needed}s%s\n" "$run_set" "" "Run $description tests"
  done
}

gather_test_files() {
  while IFS= read -r f; do
    if grep -q '@test' "$f"; then
      files+=("$f")
      file_without_header=${f/tests\/test_/}
      file_without_sh=${file_without_header/.sh/}
      run_set=${file_without_sh//_/-}
      run_sets+=("$run_set")
    fi
  done < <(find tests -name 'test_*.sh' | sort)
}

run_set_if_matching() {
  if ! check_param_count_gt "set name, test (optional)" 2 $#; then
    exit 1
  fi
  if [ "$1" == "all" ]; then
    echo "running '${run_sets[$idx]}' test suite ..."
    if ! "$HOME"/bin/bats "${files[$idx]}"; then
      echo "error running '${files[$idx]}' tests"
      exit 1
    fi
    suite_run="true"
  elif [ "$run_set" == "$1" ]; then
    if [ "$2" != "" ]; then
      echo "running test(s) matching '$2' in '${run_sets[$idx]}' test suite ..."
      if ! "$HOME"/bin/bats "${files[$idx]}" "-f" "$2"; then
        echo "error running '$2' test in '${files[$idx]}' suite"
        exit 1
      fi
    else
      echo "running '${run_sets[$idx]}' test suite ..."
      if ! "$HOME"/bin/bats "${files[$idx]}"; then
        echo "error running '${files[$idx]}' suite"
        exit 1
      fi
    fi
    complete="true"
    suite_run="true"
  fi
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
  if ! check_param_count_gt "run sets, separated by comma, or single run set then test name" 1 $#; then
    exit 1
  fi

  gather_test_files

  idx=0
  complete="false"
  suite_run="false"
  for run_set in "${run_sets[@]}"; do
    run_set_if_matching "$1" "$2"
    if [ "$complete" == "true" ]; then
      break
    fi
    ((idx++))
  done

  if [ "$suite_run" == "false" ]; then
    echo "no suites matching '$1'"
    exit 1
  fi
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

IFS=',' read -ra options <<< "$1"
if [ "$2" != "" ] && [ "${#options[@]}" -gt 1 ]; then
  echo "cannot call multiple suites with test name"
  exit 1
fi
for option in "${options[@]}"; do
  handle_param "$option" "$2"
done

# shellcheck disable=SC2086
exit 0
