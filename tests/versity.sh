#!/usr/bin/env bash

source ./tests/util_file.sh
source ./tests/iam.sh

start_versity_process() {
  if [[ $# -ne 1 ]]; then
    log 2 "start versity process function requires number"
    return 1
  fi
  if ! create_test_file_folder; then
    log 2 "error creating test log folder"
    return 1
  fi
  IFS=' ' read -r -a full_command <<< "${base_command[@]}"
  log 5 "versity command: ${full_command[*]}"
  if [ -n "$VERSITY_LOG_FILE" ]; then
    "${full_command[@]}" >> "$VERSITY_LOG_FILE" 2>&1 &
  else
    "${full_command[@]}" 2>&1 &
  fi
  # shellcheck disable=SC2181
  if [[ $? -ne 0 ]]; then
    sleep 1
    if [ -n "$VERSITY_LOG_FILE" ]; then
      log 2 "error running versitygw command: $(cat "$VERSITY_LOG_FILE")"
    fi
    return 1
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
    log 2 "versitygw failed to start: $check_result"
    if [ -n "$VERSITY_LOG_FILE" ]; then
      log 2 "log data: $(cat "$VERSITY_LOG_FILE")"
    fi
    return 1
  fi
  export versitygw_pid_"$1"
}

run_versity_app_posix() {
  if [[ $# -ne 3 ]]; then
    log 2 "run versity app w/posix command requires access ID, secret key, process number"
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
  base_command+=(posix "$LOCAL_FOLDER")
  export base_command

  if ! start_versity_process "$3"; then
    log 2 "error starting versity process"
    return 1
  fi
  return 0
}

run_versity_app_scoutfs() {
  if [[ $# -ne 3 ]]; then
    echo "run versity app w/scoutfs command requires access ID, secret key, process number"
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
  export base_command

  local versity_result
  start_versity_process "$3" || versity_result=$?
  if [[ $versity_result -ne 0 ]]; then
    echo "error starting versity process"
    return 1
  fi
  return 0
}

run_versity_app_s3() {
  if [[ $# -ne 1 ]]; then
    log 2 "run versity app w/s3 command requires process number"
    return 1
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

  if ! start_versity_process "$1"; then
    log 2 "error starting versity process"
    return 1
  fi
  return 0
}

run_versity_app() {
  if [[ $BACKEND == 'posix' ]]; then
    if ! run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"; then
      log 2 "error starting versity app"
      return 1
    fi
  elif [[ $BACKEND == 'scoutfs' ]]; then
    run_versity_app_scoutfs "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1" || result_one=$?
    if [[ $result_one -ne 0 ]]; then
      echo "error starting versity app"
      return 1
    fi
  elif [[ $BACKEND == 's3' ]]; then
    if ! run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1"; then
      log 2 "error starting versity app"
      return 1
    fi
    if ! run_versity_app_s3 "2"; then
      log 2 "error starting second versity app"
      return 1
    fi
  else
    log 2 "unrecognized backend type $BACKEND"
    return 1
  fi
  if [[ $IAM_TYPE == "s3" ]]; then
    if ! bucket_exists "s3api" "$USERS_BUCKET"; then
      if ! create_bucket "s3api" "$USERS_BUCKET"; then
        log 2 "error creating IAM bucket"
        return 1
      fi
    fi
  fi
}

stop_single_process() {
  if [[ $# -ne 1 ]]; then
    log 2 "stop single process function requires process ID"
    return 1
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
  # shellcheck disable=SC2154
  if ! stop_single_process "$versitygw_pid_1"; then
    log 2 "error stopping versity process"
  fi
  if [[ $BACKEND == 's3' ]]; then
    # shellcheck disable=SC2154
    if ! stop_single_process "$versitygw_pid_2"; then
      log 2 "error stopping versity process two"
    fi
  fi
}