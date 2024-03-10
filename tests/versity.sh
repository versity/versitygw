#!/bin/bash

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
  fi
  if [[ $RUN_VERSITYGW == "true" ]]; then
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
  fi
}

start_versity() {
  if [ -z "$VERSITYGW_TEST_ENV" ]; then
    if [ -r tests/.env ]; then
      source tests/.env
    else
      echo "Warning: no .env file found in tests folder"
    fi
  else
    # shellcheck source=./.env.default
    source "$VERSITYGW_TEST_ENV"
  fi
  if [ "$GITHUB_ACTIONS" != "true" ] && [ -r "$SECRETS_FILE" ]; then
    # shellcheck source=/.secrets
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
    base_command="ROOT_ACCESS_KEY=$AWS_ACCESS_KEY_ID ROOT_SECRET_KEY=$AWS_SECRET_ACCESS_KEY VGW_REGION=$AWS_REGION $VERSITY_EXE"
    if [ -n "$CERT" ] && [ -n "$KEY" ]; then
      base_command+=" --cert $CERT --key $KEY"
    fi
    base_command+=" $BACKEND $LOCAL_FOLDER &"
    eval "$base_command"
    versitygw_pid=$!

    export versitygw_pid VERSITY_EXE BACKEND LOCAL_FOLDER
  fi

  export versitygw_pid AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION AWS_PROFILE AWS_ENDPOINT_URL
}

stop_versity() {
  if [ "$RUN_VERSITYGW" == "false" ]; then
    return
  fi
  if [ -n "$versitygw_pid" ]; then
    if ps -p "$versitygw_pid" > /dev/null; then
      kill "$versitygw_pid"
      wait "$versitygw_pid" || true
    else
      echo "Process with PID $versitygw_pid does not exist."
    fi
  else
    echo "versitygw_pid is not set or empty."
  fi
}