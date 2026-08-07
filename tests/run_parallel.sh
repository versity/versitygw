#!/usr/bin/env bash

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

source ./tests/drivers/params.sh

DEFAULT_MAX_PARALLEL_JOBS=4
DEFAULT_DOCKER_LOG_FOLDER="$PWD/runtime/log"

check_for_finished_processes() {
  if ! check_param_count_v2 "pid array ref, suite array ref, time array ref" 3 $#; then
    return 1
  fi
  local -n pids_ref="$1" suites_ref="$2" times_ref="$3"
  local -a pid_snapshot
  local pid status run_end_time

  pid_snapshot=("${!pids_ref[@]}")
  for pid in "${pid_snapshot[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"
      status=$?
      run_end_time=$(date +%s)
      printf '%s\n' "'$pid' (${suites_ref[$pid]}) finished with status '$status' (duration: $((run_end_time-${times_ref[$pid]}))s)"
      unset "pids_ref[$pid]"
      unset "suites_ref[$pid]"
      unset "times_ref[$pid]"
    fi
  done
}

run_tests() {
  if ! check_param_count_v2 "image tag, test list, max parallel jobs, docker log folder" 4 $#; then
    return 1
  fi
  local image_tag="$1" test_list="$2" max_parallel_jobs="$3" docker_log_folder="$4"
  local test_array pids suites times timestamp test_suite end_time duration

  IFS=, read -r -a test_array <<< "$test_list"

  declare -A pids suites times
  timestamp="$(date '+%Y%m%dT%H%M%S')"

  for test_suite in "${test_array[@]}"; do
    while [ ${#pids[@]} -ge "$max_parallel_jobs" ]; do
      sleep 1
      check_for_finished_processes "pids" "suites" "times"
    done
    docker run -v "$PWD/runtime/config:/home/tester/config" -v "$docker_log_folder:/home/tester/log" -t "$image_tag" "$test_suite" > "$docker_log_folder/${test_suite}-${timestamp}.log" &
    pid=$!
    printf '%s\n' "'$test_suite' started (pid: '$pid')"
    pids[$pid]=$pid
    # shellcheck disable=SC2034
    suites[$pid]=$test_suite
    # shellcheck disable=SC2034
    times[$pid]=$(date +%s)
  done

  while [ ${#pids[@]} -gt 0 ]; do
    check_for_finished_processes "pids" "suites" "times"
    sleep 1
  done

  end_time=$(date +%s)
  duration=$((end_time-start_time))
  printf '%s\n' "duration: ${duration}s"
}

if ! check_param_count_ge_le "docker image tag, test suites (separated by comma), max parallel jobs at once (default '$DEFAULT_MAX_PARALLEL_JOBS', log folder (default '$DEFAULT_DOCKER_LOG_FOLDER')" 2 4 $#; then
  exit 1
fi

start_time=$(date +%s)
image_tag="$1"
test_list="$2"
if [ "$3" == "" ]; then
  max_parallel_jobs="$DEFAULT_MAX_PARALLEL_JOBS"
else
  if [ "$3" -le 0 ]; then
    echo "max parallel jobs must be at least 1"
    exit 1
  fi
  max_parallel_jobs="$3"
fi
if [ "$4" == "" ]; then
  docker_log_folder="$DEFAULT_DOCKER_LOG_FOLDER"
else
  docker_log_folder="$4"
fi

if ! docker image inspect "$image_tag" >/dev/null 2>&1; then
  echo "image tagged '$image_tag' doesn't exist"
  exit 1
fi

if ! mkdir -p "$docker_log_folder"; then
  echo "unable to create docker log folder '$docker_log_folder'"
  exit 1
fi

run_tests "$image_tag" "$test_list" "$max_parallel_jobs" "$docker_log_folder"
