#!/usr/bin/env bash

source ./tests/drivers/params.sh

setup_bucket_and_file() {
  if ! check_param_count "setup_bucket_and_file" "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_files "$1" "$2"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  return 0
}

setup_bucket_and_files() {
  if ! check_param_count_gt "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! create_test_files "${@:2}"; then
    log 2 "error creating test files"
    return 1
  fi
  return 0
}

setup_bucket_and_large_file() {
  if ! check_param_count "setup_bucket_and_large_file" "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! create_large_file "$2"; then
    log 2 "error creating large file"
    return 1
  fi
  return 0
}

setup_bucket_and_user() {
  if ! check_param_count "setup_bucket_and_user" "bucket, username, password, user type" 4 $#; then
    return 1
  fi
  if ! setup_bucket "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! result=$(setup_user_versitygw_or_direct "$2" "$3" "$4" "$1"); then
    log 2 "error setting up user"
    return 1
  fi
  echo "$result"
  return 0
}

setup_bucket_file_and_user() {
  if ! check_param_count "setup_bucket_file_and_user" "bucket, file, username, password, user type" 5 $#; then
    return 1
  fi
  if ! setup_bucket_and_files "$1" "$2"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  if ! result=$(setup_user_versitygw_or_direct "$3" "$4" "$5" "$1"); then
    log 2 "error setting up user"
    return 1
  fi
  echo "$result"
  return 0
}

setup_bucket_object_lock_enabled() {
  if ! check_param_count "setup_bucket_object_lock_enabled" "bucket" 1 $#; then
    return 1
  fi
  if ! bucket_cleanup_if_bucket_exists "$1"; then
    log 2 "error cleaning up bucket"
    return 1
  fi

  # in static bucket config, bucket will still exist
  if ! bucket_exists "$1"; then
    if ! create_bucket_object_lock_enabled "$1"; then
      log 2 "error creating bucket with object lock enabled"
      return 1
    fi
  fi
  return 0
}
