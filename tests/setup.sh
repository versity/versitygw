#!/usr/bin/env bash

source ./tests/env.sh
source ./tests/setup_mc.sh
source ./tests/versity.sh

# bats setup function
setup() {
  if ! check_env_vars; then
    log 2 "error checking env values"
    return 1
  fi
  if [ "$RUN_VERSITYGW" == "true" ]; then
    if ! run_versity_app; then
      log 2 "error starting versity apps"
      return 1
    fi
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
    if ! check_add_mc_alias; then
      log 2 "mc alias check/add failed"
      return 1
    fi
  fi

  export AWS_PROFILE \
    BUCKET_ONE_NAME \
    BUCKET_TWO_NAME
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
  if [[ -n "$COVERAGE_DB" ]]; then
    record_result
  fi
}
