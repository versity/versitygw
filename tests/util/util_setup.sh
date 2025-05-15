#!/usr/bin/env bash

setup_bucket_and_file() {
  if [ $# -ne 2 ]; then
    log 2 "'setup_bucket_and_file' requires bucket name, file name"
    return 1
  fi
  if ! setup_bucket_and_files "$1" "$2"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  return 0
}

setup_bucket_and_files() {
  if [ $# -lt 2 ]; then
    log 2 "'setup_bucket_and_files' requires bucket name, file names"
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
  if [ $# -ne 2 ]; then
    log 2 "'setup_bucket_and_large_file' requires bucket name, file name"
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
  if [ $# -ne 4 ]; then
    log 2 "'setup_bucket_and_user' requires bucket name, username, password, user type"
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
  if [ $# -ne 5 ]; then
    log 2 "'setup_bucket_file_and_user' requires bucket name, file, username, password, user type"
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
  if [ $# -ne 1 ]; then
    log 2 "'setup_bucket_object_lock_enabled' requires bucket name"
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
