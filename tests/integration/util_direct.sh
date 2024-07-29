#!/usr/bin/env bash

append_policy() {
  if [[ $# -ne 2 ]]; then
    log 2 "'append_policy' requires username, current policy"
}

get_canonical_id() {
  if [[ $# -ne 1 ]]; then
    log 2 "'get canonical ID' command requires username"
    return 1
  fi
}