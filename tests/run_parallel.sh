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

CONTAINER_CONFIG_FOLDER=/home/tester/config
CONTAINER_LOG_FOLDER=/home/tester/log
DEFAULT_MAX_PARALLEL_JOBS=4
DEFAULT_HOST_LOG_FOLDER="$PWD/runtime/log"
DEFAULT_HOST_CONFIG_FOLDER="$PWD/runtime/config"
DOCKERFILE="tests/Dockerfile_test_bats"

print_message() {
  if [ -n "${runner_log_file:-}" ]; then
    printf '%s\n' "$1" | tee -a "$runner_log_file"
  else
    printf '%s\n' "$1"
  fi
  if [ "${html_report_ready:-false}" == "true" ]; then
    write_html_message "$@"
  fi
}

html_escape() {
  local text="$1"
  text=${text//&/'&amp;'}
  text=${text//</'&lt;'}
  text=${text//>/'&gt;'}
  text=${text//\"/'&quot;'}
  text=${text//\'/'&#39;'}
  printf '%s' "$text"
}

html_log_url() {
  local log_path="$1" common="$html_report_dir" prefix="" relative char encoded=""
  local LC_ALL=C
  log_path="$(cd "$(dirname "$log_path")" && pwd -P)/$(basename "$log_path")"
  while [[ "$log_path" != "$common/"* ]] && [ "$common" != "/" ]; do
    common=$(dirname "$common")
    prefix+="../"
  done
  relative="$prefix${log_path#"${common%/}/"}"
  while [ -n "$relative" ]; do
    char=${relative:0:1}
    relative=${relative:1}
    case "$char" in
      [a-zA-Z0-9./_~-]) encoded+="$char" ;;
      *) printf -v char '%%%02X' "'$char"; encoded+="$char" ;;
    esac
  done
  printf '%s' "$encoded"
}

write_html_message() {
  {
    printf '<li>%s' "$(html_escape "$1")"
    if [ -n "${2:-}" ]; then
      printf ' <a href="%s">Docker log: %s</a>' "$(html_log_url "$2")" "$(html_escape "$2")"
    fi
    printf '</li>\n'
  } >> "$html_report_file"
}

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
      print_message "'$pid' (${suites_ref[$pid]}) finished with status '$status' (duration: $((run_end_time-${times_ref[$pid]}))s)" "${logs_ref[$pid]}"
      if [ "$status" -ne 0 ]; then
        test_failure=1
        print_message "log file:  ${logs_ref[$pid]}"
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
    docker run -v "$host_config_folder:$CONTAINER_CONFIG_FOLDER" -e "HOST_LOG_FOLDER=$docker_log_folder" -v "$docker_log_folder:$CONTAINER_LOG_FOLDER" "$image_tag" "$test_suite" > "$log_name" 2>&1 &
    pid=$!
    print_message "'$test_suite' started (pid: '$pid')"
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
  printf '%s\n' "Usage: $0 -l|--list"
  printf '%s\n' "Usage: $0 [--config-folder <path>] [--log-folder <path>] [--max-parallel-jobs <count>] [--build-mode <mode>] [--log-file <path>] [--html-report <path>] <docker image tag> <test suites>"
  printf '%s\n' "  -l, --list          List available test suites without running Docker."
  printf '%s\n' "  all                Use as the test suites argument to run every discovered suite."
  printf '%s\n' "  --config-folder <path> Host configuration directory (default: $DEFAULT_HOST_CONFIG_FOLDER)."
  printf '%s\n' "  --log-folder <path> Directory for suite logs (default: $DEFAULT_HOST_LOG_FOLDER)."
  printf '%s\n' "  --max-parallel-jobs <count> Maximum concurrent suites (default: $DEFAULT_MAX_PARALLEL_JOBS)."
  printf '%s\n' "  --build-mode <mode> rebuild: always build; build-if-missing: build only if absent; use-tag: use existing image (default)."
  printf '%s\n' "  --log-file <path>   Append runner status messages; relative paths use --log-folder."
  printf '%s\n' "  --html-report <path> Write a new HTML report; relative paths use --log-folder."
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
        print_message "image tagged '$image_tag' doesn't exist"
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

parse_options() {
  # Keep shared configuration and report state global for helpers and the EXIT trap.
  max_parallel_jobs="$DEFAULT_MAX_PARALLEL_JOBS"
  docker_log_folder="$DEFAULT_HOST_LOG_FOLDER"
  host_config_folder="$DEFAULT_HOST_CONFIG_FOLDER"
  build_mode="use-tag"
  runner_log_file=""
  html_report_file=""
  html_report_ready=false

  while [ $# -gt 0 ]; do
    case "$1" in
      --config-folder)
        if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
          echo "--config-folder requires a directory path" >&2
          return 1
        fi
        host_config_folder="$2"
        shift
        ;;
      --log-folder)
        if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
          echo "--log-folder requires a directory path" >&2
          return 1
        fi
        docker_log_folder="$2"
        shift
        ;;
      --max-parallel-jobs)
        if [ $# -lt 2 ] || ! [[ "$2" =~ ^[1-9][0-9]*$ ]]; then
          echo "--max-parallel-jobs requires a positive integer" >&2
          return 1
        fi
        max_parallel_jobs="$2"
        shift
        ;;
      --html-report)
        if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
          echo "--html-report requires a file path" >&2
          return 1
        fi
        html_report_file="$2"
        shift
        ;;
      --log-file)
        if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
          echo "--log-file requires a file path" >&2
          return 1
        fi
        runner_log_file="$2"
        shift
        ;;
      --build-mode)
        case "${2:-}" in
          rebuild|build-if-missing|use-tag) build_mode="$2" ;;
          *)
            echo "--build-mode requires rebuild, build-if-missing, or use-tag" >&2
            return 1
            ;;
        esac
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -l|--list)
        ./tests/run.sh -l
        exit $?
        ;;
      --)
        shift
        break
        ;;
      -*)
        echo "unknown option '$1'" >&2
        return 1
        ;;
      *)
        break
        ;;
    esac
    shift
  done

  if [ $# -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
    echo "expected image tag and test suites after options" >&2
    usage
    return 1
  fi
  image_tag="$1"
  test_list="$2"
}

resolve_test_suites() {
  if [ "$test_list" == "all" ]; then
    if ! test_list=$(./tests/run.sh -l); then
      echo "unable to list test suites" >&2
      return 1
    fi
    if [[ "$test_list" != *[![:space:]]* ]]; then
      echo "no test suites found" >&2
      return 1
    fi
  elif [[ ",$test_list," == *,all,* ]]; then
    echo "all must be used alone, not combined with other suites" >&2
    return 1
  fi
  return 0
}

initialize_reports() {
  if [ -n "$runner_log_file" ] && [[ "$runner_log_file" != /* ]]; then
    runner_log_file="${docker_log_folder%/}/$runner_log_file"
  fi
  if [ -n "$html_report_file" ] && [[ "$html_report_file" != /* ]]; then
    html_report_file="${docker_log_folder%/}/$html_report_file"
  fi
  if [ -n "$runner_log_file" ] && ! { : >> "$runner_log_file"; }; then
    echo "unable to write runner log file '$runner_log_file'" >&2
    return 1
  fi

  if [ -n "$html_report_file" ]; then
    if ! html_report_dir=$(cd "$(dirname "$html_report_file")" && pwd -P); then
      return 1
    fi
    html_report_file="$html_report_dir/$(basename "$html_report_file")"
    if [ -f "$html_report_file" ]; then
      echo "html report file '$html_report_file' already exists"
      return 1
    fi
    if [ -n "$runner_log_file" ] && [ "$runner_log_file" -ef "$html_report_file" ]; then
      echo "HTML report and text log must be different files" >&2
      return 1
    fi
    if ! printf '%s\n' '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Parallel Test Report</title></head><body><h1>Parallel Test Report</h1><ul>' > "$html_report_file"; then
      return 1
    fi
    html_report_ready=true
    trap 'printf "%s\n" "</ul></body></html>" >> "$html_report_file"' EXIT
    print_message "HTML report: $html_report_file"
  fi
}

main() {
  local start_time end_time duration
  start_time=$(date +%s)

  parse_options "$@" || return $?
  resolve_test_suites || return $?

  if ! mkdir -p "$docker_log_folder"; then
    print_message "unable to create docker log folder '$docker_log_folder'"
    return 1
  fi
  initialize_reports || return $?
  prepare_container "$image_tag" "$build_mode" || return 1

  test_failure=0
  run_tests "$image_tag" "$test_list" "$max_parallel_jobs" "$docker_log_folder"

  end_time=$(date +%s)
  duration=$((end_time-start_time))
  print_message "duration: ${duration}s"

  return "$test_failure"
}

main "$@"
