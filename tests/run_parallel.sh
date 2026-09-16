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
DOCKERFILE="tests/Dockerfile_test_bats"

check_for_finished_processes() {
  if ! check_param_count_v2 "pid array ref, suite array ref, time array ref, log array ref" 4 $#; then
    return 1
  fi
  local -n pids_ref="$1" suites_ref="$2" times_ref="$3" logs_ref="$4"
  local -a pid_snapshot
  local pid status run_end_time

  pid_snapshot=("${!pids_ref[@]}")
  for pid in "${pid_snapshot[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"
      status=$?
      run_end_time=$(date +%s)
      printf '%s\n' "'$pid' (${suites_ref[$pid]}) finished with status '$status' (duration: $((run_end_time-${times_ref[$pid]}))s)"
      if [ "$status" -ne 0 ]; then
        printf 'log file:  %s\n' "${logs_ref[$pid]}"
      fi
      unset "pids_ref[$pid]"
      unset "suites_ref[$pid]"
      unset "times_ref[$pid]"
      unset "logs_ref[$pid]"
    fi
  done
}

run_tests() {
  if ! check_param_count_v2 "image tag, test list, max parallel jobs, docker log folder" 4 $#; then
    return 1
  fi
  local image_tag="$1" test_list="$2" max_parallel_jobs="$3" docker_log_folder="$4"
  local test_array pids suites times timestamp test_suite end_time duration log_name

  IFS=, read -r -a test_array <<< "$test_list"

  declare -A pids suites times logs
  timestamp="$(date '+%Y%m%dT%H%M%S')"

  for test_suite in "${test_array[@]}"; do
    while [ ${#pids[@]} -ge "$max_parallel_jobs" ]; do
      sleep 1
      check_for_finished_processes "pids" "suites" "times" "logs"
    done
    log_name="$docker_log_folder/${test_suite}-${timestamp}.log"
    docker run -v "$PWD/runtime/config:/home/tester/config" -v "$docker_log_folder:/home/tester/log" -t "$image_tag" "$test_suite" > "$log_name" &
    pid=$!
    printf '%s\n' "'$test_suite' started (pid: '$pid')"
    pids[$pid]=$pid
    # shellcheck disable=SC2034
    suites[$pid]=$test_suite
    # shellcheck disable=SC2034
    logs[$pid]=$log_name
    # shellcheck disable=SC2034
    times[$pid]=$(date +%s)
  done

  while [ ${#pids[@]} -gt 0 ]; do
    check_for_finished_processes "pids" "suites" "times" "logs"
    sleep 1
  done
}

usage() {
  printf '%s\n' "Usage: $0 <docker image tag> <test suites> [max parallel jobs] [log folder] [--rebuild|--build-if-missing|--use-tag]"
  printf '%s\n' "  --rebuild           Rebuild the Docker image before testing."
  printf '%s\n' "  --build-if-missing  Build the Docker image only if the tag does not exist."
  printf '%s\n' "  --use-tag           Use the provided tag without building (default)."
}

build_container() {
  if ! check_param_count_v2 "image tag" 1 $#; then
    return 1
  fi
  local image_tag="$1"

  docker build -t "$image_tag" -f "$DOCKERFILE" .
}

prepare_container() {
  if ! check_param_count_v2 "image tag, build mode" 2 $#; then
    return 1
  fi
  local image_tag="$1" build_mode="$2"

  case "$build_mode" in
    rebuild)
      build_container "$image_tag"
      ;;
    build-if-missing)
      if ! docker image inspect "$image_tag" >/dev/null 2>&1; then
        build_container "$image_tag"
      fi
      ;;
    use-tag)
      if ! docker image inspect "$image_tag" >/dev/null 2>&1; then
        echo "image tagged '$image_tag' doesn't exist"
        return 1
      fi
      ;;
    *)
      echo "unknown build mode '$build_mode'"
      usage
      return 1
      ;;
  esac
}

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  usage
  exit 0
fi

if [ $# -lt 2 ]; then
  usage
  exit 1
fi

start_time=$(date +%s)

image_tag="$1"
test_list="$2"
max_parallel_jobs="$DEFAULT_MAX_PARALLEL_JOBS"
docker_log_folder="$DEFAULT_DOCKER_LOG_FOLDER"
build_mode="use-tag"
docker_log_folder_set=false
shift 2

while [ $# -gt 0 ]; do
  case "$1" in
    --rebuild)
      build_mode="rebuild"
      ;;
    --build-if-missing)
      build_mode="build-if-missing"
      ;;
    --use-tag)
      build_mode="use-tag"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ "$1" =~ ^[0-9]+$ ]]; then
        if [ "$1" -le 0 ]; then
          echo "max parallel jobs must be at least 1"
          exit 1
        fi
        max_parallel_jobs="$1"
      elif [ "$docker_log_folder_set" == "false" ]; then
        docker_log_folder="$1"
        docker_log_folder_set=true
      else
        echo "unknown option or extra parameter '$1'"
        usage
        exit 1
      fi
      ;;
  esac
  shift
done

if ! prepare_container "$image_tag" "$build_mode"; then
  exit 1
fi

if ! mkdir -p "$docker_log_folder"; then
  echo "unable to create docker log folder '$docker_log_folder'"
  exit 1
fi

run_tests "$image_tag" "$test_list" "$max_parallel_jobs" "$docker_log_folder"

end_time=$(date +%s)
duration=$((end_time-start_time))
printf '%s\n' "duration: ${duration}s"
