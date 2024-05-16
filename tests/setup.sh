#!/usr/bin/env bash

source ./tests/setup_mc.sh
source ./tests/versity.sh

# bats setup function
setup() {
  start_versity || start_result=$?
  if [[ $start_result -ne 0 ]]; then
    echo "error starting versity executable"
    return 1
  fi

  check_params || check_result=$?
  if [[ $check_result -ne 0 ]]; then
    echo "parameter check failed"
    return 1
  fi

  log 4 "Running test $BATS_TEST_NAME"
  if [[ $LOG_LEVEL -ge 5 ]]; then
    start_time=$(date +%s)
    export start_time
  fi

  if [[ $RUN_S3CMD == true ]]; then
    S3CMD_OPTS=()
    S3CMD_OPTS+=(-c "$S3CMD_CONFIG")
    S3CMD_OPTS+=(--access_key="$AWS_ACCESS_KEY_ID")
    S3CMD_OPTS+=(--secret_key="$AWS_SECRET_ACCESS_KEY")
    export S3CMD_CONFIG S3CMD_OPTS
  fi

  if [[ $RUN_MC == true ]]; then
    check_add_mc_alias || check_result=$?
    if [[ $check_result -ne 0 ]]; then
      echo "mc alias check/add failed"
      return 1
    fi
  fi

  export AWS_PROFILE \
    BUCKET_ONE_NAME \
    BUCKET_TWO_NAME
}

# make sure required environment variables for tests are defined properly
# return 0 for yes, 1 for no
check_params() {
  if [ -z "$BUCKET_ONE_NAME" ]; then
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
  if [[ -z "$LOG_LEVEL" ]]; then
    export LOG_LEVEL=2
  else
    export LOG_LEVEL
  fi
  if [[ -n "$TEST_LOG_FILE" ]]; then
    export TEST_LOG_FILE
  fi
  return 0
}

# fail a test
# param:  error message
fail() {
  log 1 "$1"
  return 1
}

# bats teardown function
teardown() {
  stop_versity
  if [[ $LOG_LEVEL -ge 5 ]]; then
    end_time=$(date +%s)
    log 4 "Total test time: $((end_time - start_time))"
  fi
}
