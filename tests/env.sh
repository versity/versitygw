#!/usr/bin/env bats

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

load ./bats-support/load
load ./bats-assert/load

check_env_vars() {
  check_universal_vars
  #if ! check_universal_vars; then
  #  log 2 "error checking universal params"
  #  return 1
  #fi
  if [[ $RUN_VERSITYGW == "true" ]]; then
    check_versity_vars
  fi
  if [[ $RUN_S3CMD == "true" ]]; then
    assert [ -n "$S3CMD_CONFIG" ]
    export S3CMD_CONFIG
  fi
  if [[ $RUN_MC == "true" ]]; then
    assert [ -n "$MC_ALIAS" ]
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

check_universal_vars() {
  if [[ $BYPASS_ENV_FILE != "true" ]]; then
    source_config_file
  fi

  if [ "$GITHUB_ACTIONS" != "true" ] && [ -r "$SECRETS_FILE" ]; then
    # shellcheck source=./tests/.secrets
    source "$SECRETS_FILE"
  else
    log 3 "Warning: no secrets file found"
  fi

  if [[ -n "$LOG_LEVEL" ]]; then
    export LOG_LEVEL_INT=$LOG_LEVEL
  fi

  assert [ -n "$AWS_ACCESS_KEY_ID" ]
  assert [ -n "$AWS_SECRET_ACCESS_KEY" ]
  assert [ -n "$AWS_REGION" ]
  assert [ -n "$AWS_PROFILE" ]
  if [ "$DIRECT" != "true" ]; then
    assert [ -n "$AWS_ENDPOINT_URL" ]
  fi
  if [ "$RUN_VERSITYGW" != "true" ] && [ "$RUN_VERSITYGW" != "false" ]; then
    fail "RUN_VERSITYGW must be 'true' or 'false'"
  fi

  assert [ -n "$BUCKET_ONE_NAME" ]
  assert [ -n "$BUCKET_TWO_NAME" ]
  assert [ -n "$RECREATE_BUCKETS" ]
  if [ "$RECREATE_BUCKETS" != "true" ] && [ "$RECREATE_BUCKETS" != "false" ]; then
    fail "RECREATE_BUCKETS must be 'true' or 'false'"
  fi
  assert [ -n "$TEST_FILE_FOLDER" ]
  # exporting these since they're needed for subshells
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION AWS_PROFILE AWS_ENDPOINT_URL
}

check_versity_vars() {
  assert [ -n "$LOCAL_FOLDER" ]
  assert [ -n "$VERSITY_EXE" ]
  assert [ -n "$BACKEND" ]
  export LOCAL_FOLDER VERSITY_EXE BACKEND

  if [ "$BACKEND" == 's3' ]; then
    assert [ -n "$AWS_ACCESS_KEY_ID_TWO" ]
    assert [ -n "$AWS_SECRET_ACCESS_KEY_TWO" ]
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
  assert [ -n "$USERNAME_ONE" ]
  assert [ -n "$PASSWORD_ONE" ]
  assert [ -n "$USERNAME_TWO" ]
  assert [ -n "$PASSWORD_TWO" ]

  if [[ -z "$IAM_TYPE" ]]; then
    export IAM_TYPE="folder"
  fi
  if [[ "$IAM_TYPE" == "folder" ]]; then
    assert [ -n "$USERS_FOLDER" ]
    if [ ! -d "$USERS_FOLDER" ]; then
      mkdir_error=$(mkdir "$USERS_FOLDER" 2>&1)
      assert_success "error creating users folder: $mkdir_error"
    fi
    IAM_PARAMS="--iam-dir=$USERS_FOLDER"
    export IAM_PARAMS
    return 0
  fi
  if [[ $IAM_TYPE == "s3" ]]; then
    assert [ -n "$USERS_BUCKET" ]
    IAM_PARAMS="--s3-iam-access $AWS_ACCESS_KEY_ID --s3-iam-secret $AWS_SECRET_ACCESS_KEY \
      --s3-iam-region us-east-1 --s3-iam-bucket $USERS_BUCKET --s3-iam-endpoint $AWS_ENDPOINT_URL \
      --s3-iam-noverify"
    export IAM_PARAMS
    return 0
  fi
  fail "unrecognized IAM_TYPE value: $IAM_TYPE"
}
