#!/usr/bin/env bash

get_iam_parameters() {
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
    iam_params="--iam-dir=$USERS_FOLDER"
    export iam_params
    return 0
  fi
  if [[ $IAM_TYPE == "s3" ]]; then
    if [[ -z "$USERS_BUCKET" ]]; then
      log 2 "if IAM type is s3, USERS_BUCKET is required"
      return 1
    fi
    log 4 "$USERS_BUCKET"
    if ! bucket_exists "s3api" "$USERS_BUCKET"; then
      log 4 "bucket doesn't exist"
      if [[ $? == 2 ]]; then
        log 2 "error checking if users bucket exists"
        return 1
      fi
      if ! create_bucket "s3api" "$USERS_BUCKET"; then
        log 2 "error creating bucket"
        return 1
      fi
      log 4 "bucket create successful"
    else
      log 4 "bucket exists"
    fi
    iam_params="--s3-iam-access $AWS_ACCESS_KEY_ID --s3-iam-secret $AWS_SECRET_ACCESS_KEY \
      --s3-iam-region us-east-1 --s3-iam-bucket $USERS_BUCKET --s3-iam-endpoint $AWS_ENDPOINT_URL \
      --s3-iam-noverify"
    export iam_params
    return 0
  fi
  log 2 "unrecognized IAM_TYPE value: $IAM_TYPE"
  return 1
}