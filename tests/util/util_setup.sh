#!/usr/bin/env bash

source ./tests/drivers/params.sh

setup_bucket_and_file() {
  if ! check_param_count_v2 "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_file_base "$1" "setup_bucket_and_files" "$2"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  return 0
}

setup_bucket_and_file_v2() {
  if ! check_param_count_v2 "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_file_base "$1" "setup_bucket_and_files_v2" "$2"; then
    log 2 "error setting up bucket and files"
    return 1
  fi
  return 0
}

setup_bucket_and_file_base() {
  if ! check_param_count_v2 "bucket, function, file name" 3 $#; then
    return 1
  fi
  if ! "$2" "$1" "$3"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  return 0
}

setup_bucket_and_files() {
  if ! check_param_count_gt "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_files_base "$1" "setup_bucket" "${@:2}"; then
    log 2 "error setting up bucket and files"
    return 1
  fi
  return 0
}

setup_bucket_and_files_v2() {
  if ! check_param_count_gt "bucket, file name" 2 $#; then
    return 1
  fi
  if ! setup_bucket_and_files_base "$1" "setup_bucket_v2" "${@:2}"; then
    log 2 "error setting up bucket and files"
    return 1
  fi
  return 0
}

setup_bucket_and_files_base() {
  if ! check_param_count_gt "bucket, setup bucket function, file name" 3 $#; then
    return 1
  fi
  if ! "$2" "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! create_test_files "${@:3}"; then
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
