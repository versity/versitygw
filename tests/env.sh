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

base_setup() {
  check_env_vars
  if [ "$RUN_VERSITYGW" == "true" ]; then
    run_versity_app
  fi
}

check_env_vars() {
  check_universal_vars
  if [[ $RUN_VERSITYGW == "true" ]]; then
    check_versity_vars
  fi
  if [[ $RUN_S3CMD == "true" ]]; then
    if [ -z "$S3CMD_CONFIG" ]; then
      log 1 "S3CMD_CONFIG param missing"
      exit 1
    fi
    export S3CMD_CONFIG
  fi
  if [[ $RUN_MC == "true" ]]; then
    if [ -z "$MC_ALIAS" ]; then
      log 1 "MC_ALIAS param missing"
      exit 1
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
      log 3 "Warning: no .env file found in tests folder"
    fi
  else
    # shellcheck source=./tests/.env.default
    source "$VERSITYGW_TEST_ENV"
  fi
}

check_aws_vars() {
  if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    log 1 "AWS_ACCESS_KEY_ID missing"
    exit 1
  fi
  if [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    log 1 "AWS_SECRET_ACCESS_KEY missing"
    exit 1
  fi
  if [ -z "$AWS_REGION" ]; then
    log 1 "AWS_REGION missing"
    exit 1
  fi
  if [ -z "$AWS_PROFILE" ]; then
    log 1 "AWS_PROFILE missing"
    exit 1
  fi
  if [ "$DIRECT" != "true" ]; then
    if [ -z "$AWS_ENDPOINT_URL" ]; then
      log 1 "AWS_ENDPOINT_URL missing"
      exit 1
    fi
  fi
  # exporting these since they're needed for subshells
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION AWS_PROFILE AWS_ENDPOINT_URL
  if [ -n "$AWS_CANONICAL_ID" ]; then
    export AWS_CANONICAL_ID
  fi
}

check_bucket_vars() {
  if [ -z "$BUCKET_ONE_NAME" ]; then
    log 1 "BUCKET_ONE_NAME missing"
    exit 1
  fi
  if [ -z "$BUCKET_TWO_NAME" ]; then
    log 1 "BUCKET_TWO_NAME missing"
    exit 1
  fi
  if [ "$RECREATE_BUCKETS" != "true" ] && [ "$RECREATE_BUCKETS" != "false" ]; then
    log 1 "RECREATE_BUCKETS must be 'true' or 'false'"
    exit 1
  fi
  if [ "$DELETE_BUCKETS_AFTER_TEST" != "true" ] && [ "$DELETE_BUCKETS_AFTER_TEST" != "false" ]; then
    log 1 "DELETE_BUCKETS_AFTER_TEST must be 'true' or 'false'"
    exit 1
  fi
  if [ "$RECREATE_BUCKETS" == "false" ] && [ "$DELETE_BUCKETS_AFTER_TEST" == "true" ]; then
    log 1 "cannot set DELETE_BUCKETS_AFTER_TEST to 'true' if RECREATE_BUCKETS is 'false'"
    exit 1
  fi
}

check_universal_vars() {
  if [[ $BYPASS_ENV_FILE != "true" ]]; then
    source_config_file
  fi
  if [ -n "$COMMAND_LOG" ]; then
    init_command_log
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
      exit 1
    fi
    export LOG_LEVEL_INT=$LOG_LEVEL
  fi
  if [ "$DIRECT" != "true" ]; then
    if [ -z "$DIRECT_POST_COMMAND_DELAY" ]; then
      DIRECT_POST_COMMAND_DELAY=0
    fi
    export DIRECT_POST_COMMAND_DELAY
  fi
  if [ -n "$MAX_FILE_DOWNLOAD_CHUNK_SIZE" ]; then
    export MAX_FILE_DOWNLOAD_CHUNK_SIZE
  fi

  check_aws_vars

  if [ "$RUN_VERSITYGW" != "true" ] && [ "$RUN_VERSITYGW" != "false" ]; then
    log 1 "RUN_VERSITYGW must be 'true' or 'false'"
    exit 1
  fi

  check_bucket_vars

  if [ -z "$TEST_FILE_FOLDER" ]; then
    log 1 "TEST_FILE_FOLDER missing"
    exit 1
  fi
  if [ ! -d "$TEST_FILE_FOLDER" ]; then
    if ! error=$(mkdir -p "$TEST_FILE_FOLDER" 2>&1); then
      log 1 "error creating test folder: $error"
      exit 1
    fi
  fi
  export TEST_FILE_FOLDER
}

delete_command_log() {
  if [ -e "$COMMAND_LOG" ]; then
    if ! error=$(rm "$COMMAND_LOG"); then
      log 2 "error removing command log: $error"
      return 1
    fi
  fi
}

init_command_log() {
  if ! delete_command_log; then
    exit 1
  fi
  echo "******** $(date +"%Y-%m-%d %H:%M:%S") $BATS_TEST_NAME COMMANDS ********" >> "$COMMAND_LOG"
}

check_versity_vars() {
  if [ -z "$LOCAL_FOLDER" ]; then
    log 1 "LOCAL_FOLDER missing"
    exit 1
  fi
  if [ ! -d "$LOCAL_FOLDER" ]; then
    if ! error=$(mkdir -p "$LOCAL_FOLDER"); then
      log 2 "error creating local posix folder: $error"
      exit 1
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
    exit 1
  fi
  if [ -z "$BACKEND" ]; then
    log 1 "BACKEND missing"
    exit 1
  fi
  export LOCAL_FOLDER VERSITY_EXE BACKEND

  if [ "$BACKEND" == 's3' ]; then
    if [ -z "$AWS_ACCESS_KEY_ID_TWO" ]; then
      log 1 "AWS_ACCESS_KEY_ID_TWO missing"
      exit 1
    fi
    if [ -z "$AWS_SECRET_ACCESS_KEY_TWO" ]; then
      log 1 "AWS_SECRET_ACCESS_KEY_TWO missing"
      exit 1
    fi
    export AWS_ACCESS_KEY_ID_TWO AWS_SECRET_ACCESS_KEY_TWO
  fi

  if [[ -r $GOCOVERDIR ]]; then
    export GOCOVERDIR=$GOCOVERDIR
  fi

  if [[ $RUN_USERS == "true" ]]; then
    check_user_vars
  fi
}

check_user_vars() {
  if [ -z "$USERNAME_ONE" ]; then
    log 1 "USERNAME_ONE missing"
    exit 1
  fi
  if [ -z "$PASSWORD_ONE" ]; then
    log 1 "PASSWORD_ONE missing"
    exit 1
  fi
  if [ -z "$USERNAME_TWO" ]; then
    log 1 "USERNAME_TWO missing"
    exit 1
  fi
  if [ -z "$PASSWORD_TWO" ]; then
    log 1 "PASSWORD_TWO missing"
    exit 1
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
      exit 1
    fi
    if [ ! -d "$USERS_FOLDER" ]; then
      if ! mkdir_error=$(mkdir "$USERS_FOLDER" 2>&1); then
        log 1 "error creating users folder: $mkdir_error"
        exit 1
      fi
    fi
    IAM_PARAMS="--iam-dir=$USERS_FOLDER"
    export IAM_PARAMS
    return 0
  fi
  if [[ $IAM_TYPE == "s3" ]]; then
    if [ -z "$USERS_BUCKET" ]; then
      log 1 "error creating USERS_BUCKET"
      exit 1
    fi
    IAM_PARAMS="--s3-iam-access $AWS_ACCESS_KEY_ID --s3-iam-secret $AWS_SECRET_ACCESS_KEY \
      --s3-iam-region us-east-1 --s3-iam-bucket $USERS_BUCKET --s3-iam-endpoint $AWS_ENDPOINT_URL \
      --s3-iam-noverify"
    export IAM_PARAMS
    return 0
  fi
  log 1 "unrecognized IAM_TYPE value: $IAM_TYPE"
  exit 1
}
