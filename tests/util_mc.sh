#!/usr/bin/env bash

# use mc tool to delete bucket and contents
# params:  bucket name
# return 0 for success, 1 for failure
delete_bucket_recursive_mc() {
  if [[ $# -ne 1 ]]; then
    echo "delete bucket recursive mc command requires bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(mc --insecure rm --recursive --force versity/"$1" 2>&1) || exit_code="$?"
  if [[ $exit_code -ne 0 ]]; then
    echo "error deleting bucket contents: $error"
    return 1
  fi
  error=$(mc --insecure rb versity/"$1" 2>&1) || exit_code="$?"
  if [[ $exit_code -ne 0 ]]; then
    echo "error deleting bucket: $error"
    return 1
  fi
  return 0
}