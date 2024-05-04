#!/usr/bin/env bash

# levels:  1 - crit, 2 - err, 3 - warn, 4 - info, 5 - debug, 6 - trace

log() {
  if [[ $# -ne 2 ]]; then
    echo "log function requires level, message"
    return 1
  fi
  if [[ $1 -gt $LOG_LEVEL ]]; then
    return 0
  fi
  log_level=""
  case "$1" in
    1) log_level="CRIT";;
    2) log_level="ERROR";;
    3) log_level="WARN";;
    4) log_level="INFO";;
    5) log_level="DEBUG";;
    6) log_level="TRACE";;
  esac
  echo "$log_level $2"
  if [[ -n "$TEST_LOG_FILE" ]]; then
    echo "$2" >> "$TEST_LOG_FILE"
  fi
}