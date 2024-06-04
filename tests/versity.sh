#!/bin/bash

source ./tests/util_file.sh

check_exe_params_versity() {
  if [ -z "$LOCAL_FOLDER" ]; then
    echo "No local storage folder set"
    return 1
  elif [ -z "$VERSITY_EXE" ]; then
    echo "No versity executable location set"
    return 1
  elif [ -z "$BACKEND" ]; then
    echo "No backend parameter set (options: 'posix')"
    return 1
  fi
  if [ "$BACKEND" == 's3' ]; then
    if [ -z "$AWS_ACCESS_KEY_ID_TWO" ]; then
      echo "missing second AWS access key ID for s3 backend"
      return 1
    fi
    if [ -z "$AWS_SECRET_ACCESS_KEY_TWO" ]; then
      echo "missing second AWS secret access key for s3 backend"
      return 1
    fi
  fi
}

check_exe_params() {
  if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo "No AWS access key set"
    return 1
  elif [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "No AWS secret access key set"
    return 1
  elif [ -z "$AWS_PROFILE" ]; then
    echo "No AWS profile set"
    return 1
  elif [ -z "$AWS_ENDPOINT_URL" ]; then
    echo "No AWS endpoint URL set"
    return 1
  elif [ -z "$MC_ALIAS" ]; then
    echo "No mc alias set"
    return 1
  elif [[ $RUN_VERSITYGW != "true" ]] && [[ $RUN_VERSITYGW != "false" ]]; then
    echo "RUN_VERSITYGW must be 'true' or 'false'"
    return 1
  elif [ -z "$USERS_FOLDER" ]; then
    echo "No users folder parameter set"
    return 1
  fi
  if [[ -r $GOCOVERDIR ]]; then
    export GOCOVERDIR=$GOCOVERDIR
  fi
  if [[ $RUN_VERSITYGW == "true" ]]; then
    local check_result
    check_exe_params_versity || check_result=$?
    if [[ $check_result -ne 0 ]]; then
      return 1
    fi
  fi
}

start_versity() {
  if [ -z "$VERSITYGW_TEST_ENV" ]; then
    if [ -r tests/.env ]; then
      source tests/.env
    else
      echo "Warning: no .env file found in tests folder"
    fi
  elif [[ $BYPASS_ENV_FILE != "true" ]]; then
    # shellcheck source=./tests/.env.default
    source "$VERSITYGW_TEST_ENV"
  fi
  if [ "$GITHUB_ACTIONS" != "true" ] && [ -r "$SECRETS_FILE" ]; then
    # shellcheck source=./tests/.secrets
    source "$SECRETS_FILE"
  else
    echo "Warning: no secrets file found"
  fi

  check_exe_params || check_result=$?
  if [[ $check_result -ne 0 ]]; then
    echo "error checking for parameters"
    return 1
  fi

  if [ "$RUN_VERSITYGW" == "true" ]; then
    run_versity_app || run_result=$?
    if [[ $run_result -ne 0 ]]; then
      echo "error starting versity apps"
      return 1
    fi
  fi

  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION AWS_PROFILE AWS_ENDPOINT_URL VERSITY_EXE
}

start_versity_process() {
  if [[ $# -ne 1 ]]; then
    echo "start versity process function requires number"
    return 1
  fi
  create_test_file_folder || create_result=$?
  if [[ $create_result -ne 0 ]]; then
    echo "error creating test log folder"
    return 1
  fi
  base_command+=(">" "$test_file_folder/versity_log_$1.txt" "2>&1")
  log 5 "versity command: ${base_command[*]}"
  ("${base_command[@]}") &
  # shellcheck disable=SC2181
  if [[ $? -ne 0 ]]; then
    echo "error running versitygw command: $(cat "$test_file_folder/versity_log_$1.txt")"
    return 1
  fi
  eval versitygw_pid_"$1"=$!
  local pid
  eval pid=\$versitygw_pid_"$1"
  sleep 1

  local proc_check
  check_result=$(kill -0 "$pid" 2>&1) || proc_check=$?
  if [[ $proc_check -ne 0 ]]; then
    echo "versitygw failed to start: $check_result"
    echo "log data: $(cat "$test_file_folder/versity_log_$1.txt")"
    return 1
  fi
  export versitygw_pid_"$1"
}

run_versity_app_posix() {
  if [[ $# -ne 3 ]]; then
    echo "run versity app w/posix command requires access ID, secret key, process number"
    return 1
  fi
  base_command=("$VERSITY_EXE" --access="$1" --secret="$2" --region="$AWS_REGION"  --iam-dir="$USERS_FOLDER")
  if [ -n "$CERT" ] && [ -n "$KEY" ]; then
    base_command+=(--cert "$CERT" --key "$KEY")
  fi
  if [ -n "$PORT" ]; then
    base_command+=(--port ":$PORT")
  fi
  base_command+=(posix "$LOCAL_FOLDER")
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
    echo "run versity app w/s3 command requires process number"
    return 1
  fi
  base_command=("$VERSITY_EXE" --port=":7071" --access="$AWS_ACCESS_KEY_ID" --secret="$AWS_SECRET_ACCESS_KEY")
  if [ -n "$CERT" ] && [ -n "$KEY" ]; then
    base_command+=(--cert "$CERT" --key "$KEY")
  fi
  base_command+=(s3 --access="$AWS_ACCESS_KEY_ID_TWO" --secret="$AWS_SECRET_ACCESS_KEY_TWO" --region="$AWS_REGION" --endpoint=https://s3.amazonaws.com)
  export base_command

  local versity_result
  start_versity_process "$1" || versity_result=$?
  if [[ $versity_result -ne 0 ]]; then
    echo "error starting versity process"
    return 1
  fi
  return 0
}

run_versity_app() {
  if [[ $BACKEND == 'posix' ]]; then
    run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1" || result_one=$?
    if [[ $result_one -ne 0 ]]; then
      echo "error starting versity app"
      return 1
    fi
  elif [[ $BACKEND == 's3' ]]; then
    run_versity_app_posix "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "1" || result_one=$?
    if [[ $result_one -ne 0 ]]; then
      echo "error starting versity app"
      return 1
    fi
    run_versity_app_s3 "2" || result_two=$?
    if [[ $result_two -ne 0 ]]; then
      echo "error starting second versity app"
      return 1
    fi
  else
    echo "unrecognized backend type $BACKEND"
    return 1
  fi
}

stop_single_process() {
  if [[ $# -ne 1 ]]; then
    echo "stop single process function requires process ID"
    return 1
  fi
  if ps -p "$1" > /dev/null; then
    kill "$1"
    wait "$1" || true
  else
    echo "Process with PID $1 does not exist."
  fi
}

stop_versity() {
  if [ "$RUN_VERSITYGW" == "false" ]; then
    return
  fi
  local result_one
  local result_two
  # shellcheck disable=SC2154
  stop_single_process "$versitygw_pid_1" || result_one=$?
  if [[ $result_one -ne 0 ]]; then
    echo "error stopping versity process"
  fi
  if [[ $BACKEND == 's3' ]]; then
    # shellcheck disable=SC2154
    stop_single_process "$versitygw_pid_2" || result_two=$?
    if [[ $result_two -ne 0 ]]; then
      echo "error stopping versity process two"
    fi
  fi
}