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

source ./tests/versity.sh

if [ -n "$BASH_VERSION" ] && [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "ERROR: This test suite requires bash 4.0 or later. Current: $BASH_VERSION" >&2
  echo "On macOS: brew install bash && add to PATH" >&2
  exit 1
fi

base_setup() {
  if ! check_env_vars; then
    log 1 "error checking env vars"
    return 1
  fi
  if [ "$RUN_VERSITYGW" == "true" ] && [ "$UNIT_TEST" != "true" ]; then
    if ! run_versity_app; then
      log 1 "error running versitygw app"
      return 1
    fi
  fi
  return 0
}

setup_test_log_file() {
  if [ -n "$TEST_LOG_FILE" ]; then
    if ! error=$(touch "$TEST_LOG_FILE.$TEST_ID" 2>&1); then
      log 1 "error creating test log file: $error"
      return 1
    fi
    export TEST_LOG_FILE
  fi
  return 0
}

remove_test_file_folder_if_desired() {
  if [ "$REMOVE_TEST_FILE_FOLDER" == "true" ]; then
    log 6 "removing test file folder"
    if ! error=$(rm -rf "${TEST_FILE_FOLDER:?}" 2>&1); then
      log 3 "unable to remove test file folder: $error"
    fi
  fi
  return 0
}

check_env_vars() {
  if ! check_universal_vars; then
    log 1 "error checking universal env vars"
    return 1
  fi
  if [[ $RUN_VERSITYGW == "true" ]]; then
    if ! check_versity_vars; then
      log 1 "error checking versitygw-related env vars"
      return 1
    fi
  fi
  if [[ $RUN_S3CMD == "true" ]]; then
    if [ -z "$S3CMD_CONFIG" ]; then
      log 1 "S3CMD_CONFIG param missing"
      return 1
    fi
    export S3CMD_CONFIG
  fi
  if [[ $RUN_MC == "true" ]]; then
    if [ -z "$MC_ALIAS" ]; then
      log 1 "MC_ALIAS param missing"
      return 1
    fi
    export MC_ALIAS
  fi
  return 0
}

source_config_file() {
  if [ -z "$VERSITYGW_TEST_ENV" ]; then
    if [ -r tests/.env ]; then
      source tests/.env
    else
      echo "Warning: no .env file found in tests folder" > /dev/stderr
    fi
  else
    # shellcheck source=./tests/.env.default
    source "$VERSITYGW_TEST_ENV"
  fi
  return 0
}

check_aws_vars() {
  if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    log 1 "AWS_ACCESS_KEY_ID missing"
    return 1
  fi
  if [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    log 1 "AWS_SECRET_ACCESS_KEY missing"
    return 1
  fi
  if [ -z "$AWS_REGION" ]; then
    log 1 "AWS_REGION missing"
    return 1
  fi
  if [ -z "$AWS_PROFILE" ]; then
    log 1 "AWS_PROFILE missing"
    return 1
  fi
  if [ "$DIRECT" != "true" ]; then
    if [ -z "$AWS_ENDPOINT_URL" ]; then
      log 1 "AWS_ENDPOINT_URL missing"
      return 1
    fi
    export SERVER_NAME="versitygw"
  else
    if [ -z "$SERVER_NAME" ]; then
      export SERVER_NAME="amazonS3"
    else
      export SERVER_NAME
    fi
  fi
  if [ -n "$TEMPLATE_MATRIX_FILE" ]; then
    export TEMPLATE_MATRIX_FILE
  fi
  # exporting these since they're needed for subshells
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION AWS_PROFILE AWS_ENDPOINT_URL
  if [ -n "$AWS_CANONICAL_ID" ]; then
    export AWS_CANONICAL_ID
  fi
  return 0
}

check_bucket_vars() {
  if [ -z "$BUCKET_ONE_NAME" ]; then
    log 1 "BUCKET_ONE_NAME missing"
    return 1
  fi
  if [ -z "$BUCKET_TWO_NAME" ]; then
    log 1 "BUCKET_TWO_NAME missing"
    return 1
  fi
  if [ "$RECREATE_BUCKETS" != "true" ] && [ "$RECREATE_BUCKETS" != "false" ]; then
    log 1 "RECREATE_BUCKETS must be 'true' or 'false'"
    return 1
  fi
  if [ "$DELETE_BUCKETS_AFTER_TEST" != "true" ] && [ "$DELETE_BUCKETS_AFTER_TEST" != "false" ]; then
    log 1 "DELETE_BUCKETS_AFTER_TEST must be 'true' or 'false'"
    return 1
  fi
  if [ "$RECREATE_BUCKETS" == "false" ] && [ "$DELETE_BUCKETS_AFTER_TEST" == "true" ]; then
    log 1 "cannot set DELETE_BUCKETS_AFTER_TEST to 'true' if RECREATE_BUCKETS is 'false'"
    return 1
  fi
  return 0
}

check_universal_vars() {
  if [[ $BYPASS_ENV_FILE != "true" ]]; then
    source_config_file
  fi
  if [ -n "$COMMAND_LOG" ]; then
    if ! init_command_log; then
      log 1 "error initializing command log"
      return 1
    fi
  fi
  if [ "$GITHUB_ACTIONS" != "true" ] && [ -r "$SECRETS_FILE" ]; then
    # shellcheck source=./tests/.secrets
    source "$SECRETS_FILE"
  else
    log 3 "Warning: no secrets file found"
  fi
  if [[ -n "$LOG_LEVEL" ]]; then
    if [[ $LOG_LEVEL -lt 2 ]]; then
      log 1 "log level must be 2 or greater"
      return 1
    fi
    export LOG_LEVEL_INT=$LOG_LEVEL
  fi
  if [ "$DIRECT" == "true" ]; then
    if [ -z "$DIRECT_POST_COMMAND_DELAY" ]; then
      DIRECT_POST_COMMAND_DELAY=0
    fi
    export DIRECT_POST_COMMAND_DELAY
  fi
  if [ -n "$MAX_FILE_DOWNLOAD_CHUNK_SIZE" ]; then
    export MAX_FILE_DOWNLOAD_CHUNK_SIZE
  fi
  if [ -n "$COVERAGE_LOG" ]; then
    export COVERAGE_LOG
  fi
  if [ -n "$QUICK_COMPARE_SIZE" ]; then
    export QUICK_COMPARE_SIZE
  fi

  if ! check_aws_vars; then
    log 1 "error checking AWS-related env vars"
    return 1
  fi

  if [ "$RUN_VERSITYGW" != "true" ] && [ "$RUN_VERSITYGW" != "false" ]; then
    log 1 "RUN_VERSITYGW must be 'true' or 'false'"
    return 1
  fi

  if ! check_bucket_vars; then
    log 1 "error checking bucket-related env vars"
    return 1
  fi

  if [ -z "$TEST_FILE_FOLDER" ]; then
    log 1 "TEST_FILE_FOLDER missing"
    return 1
  fi
  if [ ! -d "$TEST_FILE_FOLDER" ]; then
    if ! error=$(mkdir -p "$TEST_FILE_FOLDER" 2>&1); then
      log 1 "error creating test folder: $error"
      return 1
    fi
  fi
  export TEST_FILE_FOLDER
  return 0
}

check_versity_vars() {
  if [ -z "$LOCAL_FOLDER" ]; then
    log 1 "LOCAL_FOLDER missing"
    return 1
  fi
  if [ ! -d "$LOCAL_FOLDER" ]; then
    if ! error=$(mkdir -p "$LOCAL_FOLDER"); then
      log 2 "error creating local posix folder: $error"
      return 1
    fi
  fi
  if [ -n "$VERSIONING_DIR" ] && [ ! -d "$VERSIONING_DIR" ]; then
    if ! error=$(mkdir -p "$VERSIONING_DIR"); then
      log 2 "error creating versioning folder: $error"
      return 1
    fi
  fi
  if [ -z "$VERSITY_EXE" ]; then
    log 1 "VERSITY_EXE missing"
    return 1
  fi
  if [ -z "$BACKEND" ]; then
    log 1 "BACKEND missing"
    return 1
  fi
  export LOCAL_FOLDER VERSITY_EXE BACKEND

  if [ "$BACKEND" == 's3' ]; then
    if [ -z "$AWS_ACCESS_KEY_ID_TWO" ]; then
      log 1 "AWS_ACCESS_KEY_ID_TWO missing"
      return 1
    fi
    if [ -z "$AWS_SECRET_ACCESS_KEY_TWO" ]; then
      log 1 "AWS_SECRET_ACCESS_KEY_TWO missing"
      return 1
    fi
    export AWS_ACCESS_KEY_ID_TWO AWS_SECRET_ACCESS_KEY_TWO
  fi

  if [[ -n $GOCOVERDIR ]]; then
    export GOCOVERDIR=$GOCOVERDIR
  fi

  if [[ $RUN_USERS == "true" ]] && ! check_user_vars; then
    log 2 "error checking versitygw users env vars"
    return 1
  fi
  return 0
}

check_user_vars() {
  if [ -z "$USERNAME_ONE" ]; then
    log 1 "USERNAME_ONE missing"
    return 1
  fi
  if [ -z "$PASSWORD_ONE" ]; then
    log 1 "PASSWORD_ONE missing"
    return 1
  fi
  if [ -z "$USERNAME_TWO" ]; then
    log 1 "USERNAME_TWO missing"
    return 1
  fi
  if [ -z "$PASSWORD_TWO" ]; then
    log 1 "PASSWORD_TWO missing"
    return 1
  fi
  if [ "$AUTOGENERATE_USERS" != "true" ] && [ "$AUTOGENERATE_USERS" != "false" ]; then
    log 1 "AUTOGENERATE_USERS must be 'true' or 'false'"
    return 1
  fi
  if [ "$AUTOGENERATE_USERS" == "true" ] && [ "$USER_AUTOGENERATION_PREFIX" == "" ]; then
    log 1 "USER_AUTOGENERATION_PREFIX is required if AUTOGENERATE_USERS is 'true'"
    return 1
  fi
  if [ "$AUTOGENERATE_USERS" == "false" ] && [ "$CREATE_STATIC_USERS_IF_NONEXISTENT" != "true" ] && [ "$CREATE_STATIC_USERS_IF_NONEXISTENT" != "false" ]; then
    log 1 "If AUTOGENERATE_USERS is 'false', 'CREATE_STATIC_USERS_IF_NONEXISTENT' must be true or false"
    return 1
  fi

  if [[ -z "$IAM_TYPE" ]]; then
    export IAM_TYPE="folder"
  fi
  if [[ "$IAM_TYPE" == "folder" ]]; then
    if [ -z "$USERS_FOLDER" ]; then
      log 1 "USERS_FOLDER missing"
      return 1
    fi
    if [ ! -d "$USERS_FOLDER" ]; then
      if ! mkdir_error=$(mkdir "$USERS_FOLDER" 2>&1); then
        log 1 "error creating users folder: $mkdir_error"
        return 1
      fi
    fi
    IAM_PARAMS="--iam-dir=$USERS_FOLDER"
    export IAM_PARAMS
    return 0
  fi
  if [[ $IAM_TYPE == "s3" ]]; then
    if [ -z "$USERS_BUCKET" ]; then
      log 1 "error creating USERS_BUCKET"
      return 1
    fi
    IAM_PARAMS="--s3-iam-access $AWS_ACCESS_KEY_ID --s3-iam-secret $AWS_SECRET_ACCESS_KEY \
      --s3-iam-region $AWS_REGION --s3-iam-bucket $USERS_BUCKET --s3-iam-endpoint $AWS_ENDPOINT_URL \
      --s3-iam-noverify"
    export IAM_PARAMS
    return 0
  fi
  log 1 "unrecognized IAM_TYPE value: $IAM_TYPE"
  return 1
}

delete_command_log() {
  if [ -f "$COMMAND_LOG" ]; then
    if ! error=$(rm "$COMMAND_LOG"); then
      log 2 "error removing command log: $error"
      return 1
    fi
  fi
  return 0
}

init_command_log() {
  if ! delete_command_log; then
    log 1 "error deleting old command log"
    return 1
  fi
  if ! echo "******** $(date +"%Y-%m-%d %H:%M:%S") $BATS_TEST_NAME COMMANDS ********" >> "$COMMAND_LOG"; then
    log 1 "fatal error:  unable to write to file '$COMMAND_LOG'"
    return 1
  fi
  return 0
}

main_log_cleanup() {
  if [ -f "${TEST_LOG_FILE}.${TEST_ID}" ]; then
    if ! error=$(cat "${TEST_LOG_FILE}.${TEST_ID}" >> "$TEST_LOG_FILE" 2>&1); then
      log 2 "error appending temp log to main log: $error"
    fi
    if ! error=$(rm "${TEST_LOG_FILE}.${TEST_ID}" 2>&1); then
      log 2 "error deleting temp log: $error"
      return 1
    fi
  fi
  return 0
}

teardown_logs() {
  local response

  if [[ $LOG_LEVEL -ge 4 ]] || [[ -n "$TIME_LOG" ]]; then
    teardown_time_log
  fi
  if [[ -f "${TEST_LOG_FILE}.${TEST_ID}" ]]; then
    echo "********************************** END TEST LOG **********************************" >> "${TEST_LOG_FILE}.${TEST_ID}"
  fi
  if [[ -f "$COMMAND_LOG" ]]; then
    teardown_command_log
  fi
  if [ -f "${VERSITY_LOG_FILE}.${TEST_ID}.1" ]; then
    teardown_versity_log 1
  fi
  if [ -f "${VERSITY_LOG_FILE}.${TEST_ID}.2" ]; then
    teardown_versity_log 2
  fi
  if [ -f "${TEST_LOG_FILE}.${TEST_ID}" ] && [ "$BATS_TEST_COMPLETED" != "1" ]; then
    cat "${TEST_LOG_FILE}.${TEST_ID}"
  fi
  main_log_cleanup
}

teardown_time_log() {
  local end_time total_time

  end_time=$(date +%s)
  total_time=$((end_time - START_TIME))
  log 4 "Total test time: $total_time"
  if [[ -n "$TIME_LOG" ]]; then
    if ! echo "$BATS_TEST_NAME: ${total_time}s" >> "$TIME_LOG"; then
      log 3 "unable to write to '$TIME_LOG', check permissions"
      return 1
    fi
  fi
  return 0
}

teardown_command_log() {
  echo "**********************************************************************************" >> "$COMMAND_LOG"
  if [ -f "${TEST_LOG_FILE}.${TEST_ID}" ]; then
    cat "$COMMAND_LOG" >> "${TEST_LOG_FILE}.${TEST_ID}"
  elif [ "$BATS_TEST_COMPLETED" != "1" ]; then
    cat "$COMMAND_LOG"
  fi
  if ! delete_command_log; then
    log 2 "error deleting command log"
    return 1
  fi
  return 0
}

teardown_versity_log() {
  if ! check_param_count_v2 "versitygw process ID" 1 $#; then
    return 1
  fi
  echo "**********************************************************************************" >> "${VERSITY_LOG_FILE}.${TEST_ID}.$1"
  if [ -f "${TEST_LOG_FILE}.${TEST_ID}" ]; then
    cat "${VERSITY_LOG_FILE}.${TEST_ID}.$1" >> "${TEST_LOG_FILE}.${TEST_ID}"
  elif [ "$BATS_TEST_COMPLETED" != "1" ]; then
    cat "${VERSITY_LOG_FILE}.${TEST_ID}.$1"
  fi
  if ! response=$(rm "${VERSITY_LOG_FILE}.${TEST_ID}.$1" 2>&1); then
    log 3 "error deleting log file '${VERSITY_LOG_FILE}.${TEST_ID}.$1': $response"
  fi
  return 0
}
