#!/usr/bin/env bats

setup() {

  if [ "$GITHUB_ACTIONS" != "true" ] && [ -r .secrets ]; then
    source .secrets
  else
    echo "Warning: no secrets file found"
  fi
  if [ -z "$VERSITYGW_TEST_ENV" ]; then
    if [ -r tests/.env ]; then
      source tests/.env
    else
      echo "Warning: no .env file found in tests folder"
    fi
  else
    echo "$VERSITYGW_TEST_ENV"
    # shellcheck source=./.env.default
    source "$VERSITYGW_TEST_ENV"
  fi

  if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo "No AWS access key set"
    return 1
  elif [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "No AWS secret access key set"
    return 1
  elif [ -z "$VERSITY_EXE" ]; then
    echo "No versity executable location set"
    return 1
  elif [ -z "$BACKEND" ]; then
    echo "No backend parameter set (options: 'posix')"
    return 1
  elif [ -z "$AWS_REGION" ]; then
    echo "No AWS region set"
    return 1
  elif [ -z "$AWS_PROFILE" ]; then
    echo "No AWS profile set"
    return 1
  elif [ -z "$LOCAL_FOLDER" ]; then
    echo "No local storage folder set"
    return 1
  elif [ -z "$AWS_ENDPOINT_URL" ]; then
    echo "No AWS endpoint URL set"
    return 1
  elif [ -z "$BUCKET_ONE_NAME" ]; then
    echo "No bucket one name set"
    return 1
  elif [ -z "$BUCKET_TWO_NAME" ]; then
    echo "No bucket two name set"
    return 1
  elif [ -z "$RECREATE_BUCKETS" ]; then
    echo "No recreate buckets parameter set"
    return 1
  elif [[ $RECREATE_BUCKETS != "true" ]] && [[ $RECREATE_BUCKETS != "false" ]]; then
    echo "RECREATE_BUCKETS must be 'true' or 'false'"
    return 1
  fi

  ROOT_ACCESS_KEY="$AWS_ACCESS_KEY_ID" ROOT_SECRET_KEY="$AWS_SECRET_ACCESS_KEY" "$VERSITY_EXE" "$BACKEND" "$LOCAL_FOLDER" &

  export AWS_REGION
  export AWS_PROFILE
  export AWS_ENDPOINT_URL
  export LOCAL_FOLDER
  export BUCKET_ONE_NAME
  export BUCKET_TWO_NAME

  versitygw_pid=$!
  export versitygw_pid
}

fail() {
  echo "$1"
  return 1
}

teardown() {
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
