#!/usr/bin/env bash

get_object_lock_configuration() {
  record_command "get-object-lock-configuration" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "'get object lock configuration' command missing bucket name"
    return 1
  fi
  if ! lock_config=$(aws --no-verify-ssl s3api get-object-lock-configuration --bucket "$1" 2>&1); then
    log 2 "error obtaining lock config: $lock_config"
    # shellcheck disable=SC2034
    get_object_lock_config_err=$lock_config
    return 1
  fi
  lock_config=$(echo "$lock_config" | grep -v "InsecureRequestWarning")
  return 0
}