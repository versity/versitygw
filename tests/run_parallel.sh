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
    docker run -v "$PWD/runtime/config:/home/tester/config" -e "HOST_LOG_FOLDER=$docker_log_folder" -v "$docker_log_folder:/home/tester/log" "$image_tag" "$test_suite" > "$log_name" 2>&1 &
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
  printf '%s\n' "Usage: $0 <docker image tag> <test suites> [max parallel jobs] [log folder] [--rebuild|--build-if-missing|--use-tag] [--log-file <path>] [--html-report <path>]"
  printf '%s\n' "  -l, --list          List available test suites without running Docker."
  printf '%s\n' "  --rebuild           Rebuild the Docker image before testing."
  printf '%s\n' "  --build-if-missing  Build the Docker image only if the tag does not exist."
  printf '%s\n' "  --use-tag           Use the provided tag without building (default)."
  printf '%s\n' "  --log-file <path>   Append runner status messages to a file as well as stdout."
  printf '%s\n' "  --html-report <path> Write an HTML status report with links to suite logs (overwrites)."
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

if [ "$1" == "-l" ] || [ "$1" == "--list" ]; then
  ./tests/run.sh -l
  exit $?
fi

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
runner_log_file=""
html_report_file=""
html_report_ready=false
docker_log_folder_set=false
shift 2

while [ $# -gt 0 ]; do
  case "$1" in
    --html-report)
      if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
        echo "--html-report requires a file path" >&2
        exit 1
      fi
      html_report_file="$2"
      shift
      ;;
    --log-file)
      if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
        echo "--log-file requires a file path" >&2
        exit 1
      fi
      runner_log_file="$2"
      shift
      ;;
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

if [ -n "$runner_log_file" ] && ! { : >> "$runner_log_file"; }; then
  echo "unable to write runner log file '$runner_log_file'" >&2
  exit 1
fi

if [ -n "$html_report_file" ]; then
  if ! html_report_dir=$(cd "$(dirname "$html_report_file")" && pwd -P); then
    exit 1
  fi
  html_report_file="$html_report_dir/$(basename "$html_report_file")"
  if [ -n "$runner_log_file" ] && [ "$runner_log_file" -ef "$html_report_file" ]; then
    echo "HTML report and text log must be different files" >&2
    exit 1
  fi
  if ! printf '%s\n' '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Parallel Test Report</title></head><body><h1>Parallel Test Report</h1><ul>' > "$html_report_file"; then
    exit 1
  fi
  html_report_ready=true
  trap 'printf "%s\n" "</ul></body></html>" >> "$html_report_file"' EXIT
  print_message "HTML report: $html_report_file"
fi

if ! prepare_container "$image_tag" "$build_mode"; then
  exit 1
fi

if ! mkdir -p "$docker_log_folder"; then
  print_message "unable to create docker log folder '$docker_log_folder'"
  exit 1
fi

test_failure=0
run_tests "$image_tag" "$test_list" "$max_parallel_jobs" "$docker_log_folder"

end_time=$(date +%s)
duration=$((end_time-start_time))
print_message "duration: ${duration}s"

exit "$test_failure"
