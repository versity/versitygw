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
  echo "$2"
}