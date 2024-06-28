#!/usr/bin/env bash

check_env_vars() {
  if ! check_universal_vars; then
    log 2 "error checking universal params"
    return 1
  fi
  if [[ $RUN_VERSITYGW == "true" ]]; then
    if ! check_versity_vars; then
      log 2 "error checking versity params"
      return 1
    fi
  fi
  if [[ $RUN_S3CMD == "true" ]]; then
    if [[ -z "$S3CMD_CONFIG" ]]; then
      log 2 "running s3cmd commands requires S3CMD_CONFIG param"
      return 1
    fi
    export S3CMD_CONFIG
  fi
  if [[ $RUN_MC == "true" ]]; then
    if [ -z "$MC_ALIAS" ]; then
      log 2 "running mc tests requires MC_ALIAS param"
      return 1
    fi
    export MC_ALIAS
  fi
  return 0
}

check_universal_vars() {
  if [[ $BYPASS_ENV_FILE != "true" ]]; then
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
  if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    log 2 "No AWS access key set"
    return 1
  elif [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    log 2 "No AWS secret access key set"
    return 1
  elif [ -z "$AWS_REGION" ]; then
    log 2 "No AWS region set"
    return 1
  elif [ -z "$AWS_PROFILE" ]; then
    log 2 "No AWS profile set"
    return 1
  elif [ "$DIRECT" != "true" ] && [ -z "$AWS_ENDPOINT_URL" ]; then
    log 2 "No AWS endpoint URL set"
    return 1
  elif [[ $RUN_VERSITYGW != "true" ]] && [[ $RUN_VERSITYGW != "false" ]]; then
    log 2 "RUN_VERSITYGW must be 'true' or 'false'"
    return 1
  elif [ -z "$BUCKET_ONE_NAME" ]; then
    log 2 "No bucket one name set"
    return 1
  elif [ -z "$BUCKET_TWO_NAME" ]; then
    log 2 "No bucket two name set"
    return 1
  elif [ -z "$RECREATE_BUCKETS" ]; then
    log 2 "No recreate buckets parameter set"
    return 1
  elif [[ $RECREATE_BUCKETS != "true" ]] && [[ $RECREATE_BUCKETS != "false" ]]; then
    log 2 "RECREATE_BUCKETS must be 'true' or 'false'"
    return 1
  fi
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION AWS_PROFILE AWS_ENDPOINT_URL RUN_VERSITYGW \
    BUCKET_ONE_NAME BUCKET_TWO_NAME RECREATE_BUCKETS
  if [[ -n "$TEST_LOG_FILE" ]]; then
    export TEST_LOG_FILE
  fi
  if [[ -n "$VERSITY_LOG_FILE" ]]; then
    export VERSITY_LOG_FILE
  fi
  if [[ -n "$DIRECT" ]]; then
    export DIRECT
  fi
}

check_versity_vars() {
  if [ -z "$LOCAL_FOLDER" ]; then
    log 2 "No local storage folder set"
    return 1
  elif [ -z "$VERSITY_EXE" ]; then
    log 2 "No versity executable location set"
    return 1
  elif [ -z "$BACKEND" ]; then
    log 2 "No backend parameter set (options: 'posix', 's3')"
    return 1
  fi
  export LOCAL_FOLDER VERSITY_EXE BACKEND
  if [ "$BACKEND" == 's3' ]; then
    if [ -z "$AWS_ACCESS_KEY_ID_TWO" ]; then
      log 2 "missing second AWS access key ID for s3 backend"
      return 1
    fi
    if [ -z "$AWS_SECRET_ACCESS_KEY_TWO" ]; then
      log 2 "missing second AWS secret access key for s3 backend"
      return 1
    fi
    export AWS_ACCESS_KEY_ID_TWO AWS_SECRET_ACCESS_KEY_TWO
  fi
  if [[ -r $GOCOVERDIR ]]; then
    export GOCOVERDIR=$GOCOVERDIR
  fi
  if [[ $RUN_USERS == "true" ]]; then
    if ! check_user_vars; then
      log 2 "error setting user vars"
      return 1
    fi
  fi
}

check_user_vars() {
  if [[ -z "$IAM_TYPE" ]]; then
    export IAM_TYPE="folder"
  fi
  if [[ "$IAM_TYPE" == "folder" ]]; then
    if [[ -z "$USERS_FOLDER" ]]; then
      log 2 "if IAM type is folder (or not set), USERS_FOLDER parameter is required"
      return 1
    fi
    if [ ! -d "$USERS_FOLDER" ]; then
      if mkdir_error=$(mkdir "$USERS_FOLDER" 2>&1); then
        log 2 "error creating users folder: $mkdir_error"
        return 1
      fi
    fi
    IAM_PARAMS="--iam-dir=$USERS_FOLDER"
    export IAM_PARAMS
    return 0
  fi
  if [[ $IAM_TYPE == "s3" ]]; then
    if [[ -z "$USERS_BUCKET" ]]; then
      log 2 "if IAM type is s3, USERS_BUCKET is required"
      return 1
    fi
    IAM_PARAMS="--s3-iam-access $AWS_ACCESS_KEY_ID --s3-iam-secret $AWS_SECRET_ACCESS_KEY \
      --s3-iam-region us-east-1 --s3-iam-bucket $USERS_BUCKET --s3-iam-endpoint $AWS_ENDPOINT_URL \
      --s3-iam-noverify"
    export IAM_PARAMS
    return 0
  fi
  log 2 "unrecognized IAM_TYPE value: $IAM_TYPE"
  return 1
}
