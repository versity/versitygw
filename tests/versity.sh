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

source ./tests/commands/list_buckets.sh

start_versity_process() {
  if ! check_param_count_gt "versity app index, command array" 2 $#; then
    exit 1
  fi
  local response process_id

  if ! response=$(build_run_and_log_command "$1" "${@:2}" 2>&1); then
    log 2 "error building, logging, and/or running 'versitygw' executable: $response"
    return 1
  fi
  process_id="$response"

  printf -v "VERSITYGW_PID_$1" '%s' "$process_id"
  export VERSITYGW_PID_"$1"

  return 0
}

build_run_and_log_command() {
  if ! check_param_count_gt "versitygw process number (1 or 2), command array" 2 $#; then
    return 1
  fi
  local response full_command versitygw_log_file_name="" pid check_result

  IFS=' ' read -r -a full_command <<< "${@:2}"
  log 5 "versity command: ${full_command[*]}"
  if [ -n "$COMMAND_LOG" ]; then
    if ! response=$(mask_args "${full_command[*]}" 2>&1); then
      log 2 "error masking versitygw command"
      return 1
    fi
    # shellcheck disable=SC2154
    echo "$response" >> "$COMMAND_LOG"
  fi
  if [ -n "$VERSITY_LOG_FILE" ]; then
    versitygw_log_file_name="$VERSITY_LOG_FILE.$TEST_ID".$1
    echo "****************************** VERSITYGW $1 LOG ***********************************" >> "$versitygw_log_file_name"
    "${full_command[@]}" >> "$versitygw_log_file_name" 2>&1 &
  else
    "${full_command[@]}" >/dev/null 2>&1 &
  fi

  pid="$!"
  if ! verify_process_started "$pid" "$versitygw_log_file_name"; then
    return 1
  fi

  echo "$pid"
  return 0
}

verify_process_started() {
  if ! check_param_count_ge_le "pid, log file (if any)" 1 2 $#; then
    return 1
  fi
  local check_result process_running="false" proc_state

  for ((check_num=1; check_num<=3; check_num++)); do
    sleep 1
    if [ "$process_running" == "false" ] && check_result=$(kill -0 "$1" 2>&1); then
      process_running="true"
    fi
    if [ "$process_running" == "true" ]; then
      proc_state=$(ps -p "$1" -o state= 2>/dev/null | tr -d ' ')
      if [ "$proc_state" != "Z" ] && list_buckets_rest "" "" >/dev/null; then
        return 0
      fi
    fi
  done

  if [ "$process_running" == "false" ]; then
    log 1 "versitygw failed to start or crashed: $check_result"
  elif [[ "$proc_state" == "Z" ]]; then
    log 1 "versitygw process running in zombie state"
  else
    log 1 "process running in state '$proc_state', but not communicating properly"
  fi
  if [[ -n "$2" ]]; then
    log 1 "log data: '$(cat "$2")'"
  fi
  return 1
}

run_versity_app_posix() {
  if ! check_param_count "run_versity_app_posix" "access ID, secret key, versityid app index" 3 $#; then
    return 1
  fi
  base_command=("$VERSITY_EXE" --access="$1" --secret="$2" --region="$AWS_REGION")
  if [ -n "$RUN_USERS" ]; then
    # shellcheck disable=SC2153
    IFS=' ' read -r -a iam_array <<< "$IAM_PARAMS"
  fi
  base_command+=("${iam_array[@]}")
  if [ -n "$CERT" ] && [ -n "$KEY" ]; then
    base_command+=(--cert "$CERT" --key "$KEY")
  fi
  if [ -n "$PORT" ]; then
    base_command+=(--port ":$PORT")
  fi
  base_command+=(posix)
  if [ -n "$VERSIONING_DIR" ]; then
    base_command+=(--versioning-dir "$VERSIONING_DIR")
  fi
  base_command+=("$LOCAL_FOLDER")

  if ! start_versity_process "$3" "${base_command[@]}"; then
    log 1 "error starting versity process"
    return 1
  fi
  return 0
}

run_versity_app_scoutfs() {
  if ! check_param_count "run_versity_app_scoutfs" "access ID, secret key, versityid app index" 3 $#; then
    return 1
  fi
  base_command=("$VERSITY_EXE" --access="$1" --secret="$2" --region="$AWS_REGION"  --iam-dir="$USERS_FOLDER")
  if [ -n "$CERT" ] && [ -n "$KEY" ]; then
    base_command+=(--cert "$CERT" --key "$KEY")
  fi
  if [ -n "$PORT" ]; then
    base_command+=(--port ":$PORT")
  fi
  base_command+=(scoutfs "$LOCAL_FOLDER")

  if ! start_versity_process "$3" "${base_command[@]}"; then
    log 1 "error starting versity process"
    return 1
  fi
  return 0
}

run_versity_app_s3() {
  if ! check_param_count "run_versity_app_s3" "versityid app index" 1 $#; then
    return 1
  fi
  base_command=("$VERSITY_EXE" --access="$AWS_ACCESS_KEY_ID" --secret="$AWS_SECRET_ACCESS_KEY" --region="$AWS_REGION")
  if [ -n "$CERT" ] && [ -n "$KEY" ]; then
    base_command+=(--cert "$CERT" --key "$KEY")
  fi
  if [ -n "$PORT_TWO" ]; then
    base_command+=(--port ":$PORT_TWO")
  else
    base_command+=(--port ":7071")
  fi
  base_command+=(s3 --access="$AWS_ACCESS_KEY_ID_TWO" --secret="$AWS_SECRET_ACCESS_KEY_TWO" --region="$AWS_REGION" --endpoint=https://s3.amazonaws.com)

  if ! start_versity_process "$1" "${base_command[@]}"; then
    log 2 "error starting versity process"
    return 1
  fi
  return 0
}

run_versity_app() {
  if [[ $BACKEND == 'posix' ]]; then
    if ! run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"; then
      return 1
    fi
  elif [[ $BACKEND == 'scoutfs' ]]; then
    if ! run_versity_app_scoutfs "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"; then
      return 1
    fi
  elif [[ $BACKEND == 's3' ]]; then
    if ! run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"; then
      return 1
    fi
    if ! run_versity_app_s3 "2"; then
      return 1
    fi
  else
    log 1 "unrecognized backend type $BACKEND"
    return 1
  fi
  if [[ $IAM_TYPE != "s3" ]]; then
    return 0
  fi
  if bucket_exists "$USERS_BUCKET"; then
    return 0
  fi
  if ! create_bucket "s3api" "$USERS_BUCKET"; then
    log 1 "error creating IAM bucket"
    teardown
    return 1
  fi
  return 0
}

stop_versity_process() {
  if ! check_param_count "stop_single_process" "versitygw PID" 1 $#; then
    return 1
  fi
  log 5 "stop process with ID: $1"
  # shellcheck disable=SC2086
  if ps_result=$(ps -p $1 2>&1) > /dev/null; then
    kill "$1"
    wait "$1" 2>/dev/null || true
  else
    log 3 "error stopping versity app: $ps_result"
  fi
}

check_versity_process_status() {
  local status_one="" status_two=""

  status_one="none"
  status_two="none"
  if [ "$RUN_VERSITYGW" == "true" ]; then
    if [[ -n "$VERSITYGW_PID_1" ]] && verify_process_started "$VERSITYGW_PID_1" >/dev/null; then
      status_one="running"
    else
      status_one="failed"
    fi
    if [ "$BACKEND" == "s3" ]; then
      if [ -n "$VERSITYGW_PID_2" ] && verify_process_started "$VERSITYGW_PID_2" >/dev/null; then
        status_two="running"
      else
        status_two="failed"
      fi
    fi
  fi
  echo "$status_one $status_two"
  return 0
}
