#!/usr/bin/env bash

block_delete_object_without_permission() {
  if [ $# -ne 4 ]; then
    log 2 "'attempt_delete_object_without_permission' requires bucket, file, username, password"
    return 1
  fi
  if delete_object_with_user "s3api" "$1" "$2" "$3" "$4"; then
    log 2 "able to delete object despite lack of permissions"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$delete_object_error" != *"Access Denied"* ]]; then
    log 2 "invalid delete object error: $delete_object_error"
    return 1
  fi
  return 0
}