#!/usr/bin/env bash

list_object_versions() {
  if [[ $# -ne 1 ]]; then
    log 2 "'list object versions' command requires bucket name"
    return 1
  fi
  versions=$(aws --no-verify-ssl s3api list-object-versions --bucket "$1") || local list_result=$?
  if [[ $list_result -ne 0 ]]; then
    log 2 "error listing object versions: $versions"
    return 1
  fi
  export versions
  return 0
}