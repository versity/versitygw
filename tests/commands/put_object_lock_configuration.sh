#!/usr/bin/env bash

put_object_lock_configuration() {
  if [[ $# -ne 4 ]]; then
    log 2 "'put-object-lock-configuration' command requires bucket name, enabled, mode, period"
    return 1
  fi
  local config="{\"ObjectLockEnabled\": \"$2\", \"Rule\": {\"DefaultRetention\": {\"Mode\": \"$3\", \"Days\": $4}}}"
  if ! error=$(aws --no-verify-ssl s3api put-object-lock-configuration --bucket "$1" --object-lock-configuration "$config" 2>&1); then
    log 2 "error putting object lock configuration: $error"
    return 1
  fi
  return 0
}

put_object_lock_configuration_disabled() {
  if [[ $# -ne 1 ]]; then
    log 2 "'put-object-lock-configuration' disable command requires bucket name"
    return 1
  fi
  local config="{\"ObjectLockEnabled\": \"Enabled\"}"
  if ! error=$(aws --no-verify-ssl s3api put-object-lock-configuration --bucket "$1" --object-lock-configuration "$config" 2>&1); then
    log 2 "error putting object lock configuration: $error"
    return 1
  fi
  return 0
}
