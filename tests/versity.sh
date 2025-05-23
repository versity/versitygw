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

source ./tests/util/util_file.sh

start_versity_process() {
  if ! check_param_count "start_versity_process" "versity app index" 1 $#; then
    exit 1
  fi
  build_run_and_log_command
  # shellcheck disable=SC2181
  if [[ $? -ne 0 ]]; then
    sleep 1
    if [ -n "$VERSITY_LOG_FILE" ]; then
      log 1 "error running versitygw command: $(cat "$VERSITY_LOG_FILE")"
      exit 1
    fi
    exit 1
  fi
  eval versitygw_pid_"$1"=$!
  if [ -n "$VERSITY_LOG_FILE" ]; then
    process_info="Versity process $1, PID $!"
    echo "$process_info" >> "$VERSITY_LOG_FILE"
  fi
  log 4 "$process_info"
  local pid
  eval pid=\$versitygw_pid_"$1"
  sleep 1

  if ! check_result=$(kill -0 "$pid" 2>&1); then
    log 1 "versitygw failed to start: $check_result"
    if [ -n "$VERSITY_LOG_FILE" ]; then
      log 1 "log data: $(cat "$VERSITY_LOG_FILE")"
    fi
    exit 1
  fi
  export versitygw_pid_"$1"
}

build_run_and_log_command() {
  IFS=' ' read -r -a full_command <<< "${base_command[@]}"
  log 5 "versity command: ${full_command[*]}"
  if [ -n "$COMMAND_LOG" ]; then
    mask_args "${full_command[*]}"
    # shellcheck disable=SC2154
    echo "${masked_args[@]}" >> "$COMMAND_LOG"
  fi
  if [ -n "$VERSITY_LOG_FILE" ]; then
    "${full_command[@]}" >> "$VERSITY_LOG_FILE" 2>&1 &
  else
    "${full_command[@]}" 2>&1 &
  fi
}

run_versity_app_posix() {
  if ! check_param_count "run_versity_app_posix" "access ID, secret key, versityid app index" 3 $#; then
    exit 1
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
  # TODO remove or change
  base_command+=(posix)
  if [ -n "$VERSIONING_DIR" ]; then
    base_command+=(--versioning-dir "$VERSIONING_DIR")
  fi
  base_command+=("$LOCAL_FOLDER")
  export base_command

  start_versity_process "$3"
  return 0
}

run_versity_app_scoutfs() {
  if ! check_param_count "run_versity_app_scoutfs" "access ID, secret key, versityid app index" 3 $#; then
    exit 1
  fi
  base_command=("$VERSITY_EXE" --access="$1" --secret="$2" --region="$AWS_REGION"  --iam-dir="$USERS_FOLDER")
  if [ -n "$CERT" ] && [ -n "$KEY" ]; then
    base_command+=(--cert "$CERT" --key "$KEY")
  fi
  if [ -n "$PORT" ]; then
    base_command+=(--port ":$PORT")
  fi
  base_command+=(scoutfs "$LOCAL_FOLDER")
  export base_command

  start_versity_process "$3"
  return 0
}

run_versity_app_s3() {
  if ! check_param_count "run_versity_app_s3" "versityid app index" 1 $#; then
    exit 1
  fi
  base_command=("$VERSITY_EXE" --access="$AWS_ACCESS_KEY_ID" --secret="$AWS_SECRET_ACCESS_KEY")
  if [ -n "$CERT" ] && [ -n "$KEY" ]; then
    base_command+=(--cert "$CERT" --key "$KEY")
  fi
  if [ -n "$PORT_TWO" ]; then
    base_command+=(--port ":$PORT_TWO")
  else
    base_command+=(--port ":7071")
  fi
  base_command+=(s3 --access="$AWS_ACCESS_KEY_ID_TWO" --secret="$AWS_SECRET_ACCESS_KEY_TWO" --region="$AWS_REGION" --endpoint=https://s3.amazonaws.com)
  export base_command

  start_versity_process "$1"
  return 0
}

run_versity_app() {
  if [[ $BACKEND == 'posix' ]]; then
    run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"
  elif [[ $BACKEND == 'scoutfs' ]]; then
    run_versity_app_scoutfs "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"
  elif [[ $BACKEND == 's3' ]]; then
    run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"
    run_versity_app_s3 "2"
  else
    log 1 "unrecognized backend type $BACKEND"
    exit 1
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
    exit 1
  fi
}

stop_single_process() {
  if ! check_param_count "stop_single_process" "versitygw PID" 1 $#; then
    exit 1
  fi
  log 5 "stop process with ID: $1"
  # shellcheck disable=SC2086
  if ps_result=$(ps -p $1 2>&1) > /dev/null; then
    kill "$1"
    wait "$1" || true
  else
    log 3 "error stopping versity app: $ps_result"
  fi
}

stop_versity() {
  if [ "$RUN_VERSITYGW" == "false" ]; then
    return
  fi
  if [[ -z "$versitygw_pid_1" ]]; then
    return
  fi
  # shellcheck disable=SC2154
  if ! stop_single_process "$versitygw_pid_1"; then
    log 2 "error stopping versity process"
  fi
  if [[ $BACKEND == 's3' ]] && [[ -n "$versitygw_pid_2" ]]; then
    # shellcheck disable=SC2154
    if ! stop_single_process "$versitygw_pid_2"; then
      log 2 "error stopping versity process two"
    fi
  fi
}