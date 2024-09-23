#!/usr/bin/env bash

get_time_seconds_in_future() {
  if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    log 2 "'get_time_seconds_in_future' requires seconds, zone format (optional)"
    return 1
  fi
  os_name="$(uname)"
  if [[ "$os_name" == "Darwin" ]]; then
    now=$(date -u +"%Y-%m-%dT%H:%M:%S$2")
    later=$(date -j -v "+${1}S" -f "%Y-%m-%dT%H:%M:%S$2" "$now" +"%Y-%m-%dT%H:%M:%S$2")
  else
    now=$(date +"%Y-%m-%dT%H:%M:%S$2")
    # shellcheck disable=SC2034
    later=$(date -d "$now $1 seconds" +"%Y-%m-%dT%H:%M:%S$2")
  fi
  echo "$later"
}
