#!/usr/bin/env bash

get_object_lock_configuration() {
  if [[ $# -ne 1 ]]; then
    log 2 "'get object lock configuration' command missing bucket name"
    return 1
  fi
  lock_config=$(aws --no-verify-ssl s3api get-object-lock-configuration --bucket "$1") || local get_result=$?
  if [[ $get_result -ne 0 ]]; then
    log 2 "error obtaining lock config: $lock_config"
    return 1
  fi
  export lock_config
  return 0
}