#!/usr/bin/env bash

# levels:  1 - crit, 2 - err, 3 - warn, 4 - info, 5 - debug, 6 - trace

log() {
  if [[ $# -ne 2 ]]; then
    echo "log function requires level, message"
    return 1
  fi
  # shellcheck disable=SC2153
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
    *) echo "invalid log level $1"; return 1
  esac
  if [[ "$2" == *"secret_key"* ]]; then
    log_mask $log_level "$2"
    return 0
  fi
  echo "$log_level $2"
  if [[ -n "$TEST_LOG_FILE" ]]; then
    echo "$log_level $2" >> "$TEST_LOG_FILE"
  fi
}

log_mask() {
  if [[ $# -ne 2 ]]; then
    echo "mask and log requires level, string"
    return 1
  fi
  local masked_args=()  # Initialize an array to hold the masked arguments

  IFS=' ' read -r -a array <<< "$2"

  for arg in "${array[@]}"; do
    if [[ "$arg" == --secret_key=* ]]; then
      masked_args+=("--secret_key=********")
    else
      masked_args+=("$arg")
    fi
  done

  echo "$log_level ${masked_args[*]}"
  if [[ -n "$TEST_LOG_FILE" ]]; then
    echo "$log_level ${masked_args[*]}" >> "$TEST_LOG_FILE"
  fi
}
