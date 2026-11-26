#!/usr/bin/env bash

# Copyright 2026 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# retry runs a command again when it fails, so that one transient network
# error, such as a reset connection, an unreachable mirror or a stalled
# download, doesn't fail a whole CI job. Run the script, or source it to
# define the retry function, which can also run shell functions:
#
#   retry [-n attempts] [-t timeout] [-d delay] [-m max-delay] [--] command [args...]
#
#   -n  how many times to run the command at most
#       (default: $RETRY_ATTEMPTS, else 5)
#   -t  seconds one attempt may run before it is stopped, 0 for no limit
#       (default: $RETRY_TIMEOUT, else 300)
#   -d  seconds to wait after the first failure, doubled after each further
#       failure (default: $RETRY_DELAY, else 10)
#   -m  the longest wait between two attempts before jitter, in seconds
#       (default: $RETRY_MAX_DELAY, else 120)
#
# Each wait gets up to half as long again of random jitter, so parallel jobs
# that failed together don't retry together. An attempt that runs out of time
# fails with status 124. A command that can't be run (status 126 or 127) isn't
# retried, and nothing is retried after a SIGINT or SIGTERM, such as when a
# workflow run is cancelled. The exit status is that of the last attempt.
#
# A real failure is retried as well, so wrap the command that downloads, not
# a build or a test that downloads on the side.

# retry runs _retry in a subshell, so the options and traps it sets don't leak
# into a script that sources this file.
retry() (
  _retry "$@"
)

# _retry is retry without the subshell, which the script runs directly, so
# its traps are in the process that receives a cancellation.
_retry() {
  set +eu

  attempts=${RETRY_ATTEMPTS:-5}
  timeout=${RETRY_TIMEOUT:-300}
  delay=${RETRY_DELAY:-10}
  max_delay=${RETRY_MAX_DELAY:-120}

  OPTIND=1
  while getopts ':n:t:d:m:' opt; do
    case $opt in
    n) attempts=$OPTARG ;;
    t) timeout=$OPTARG ;;
    d) delay=$OPTARG ;;
    m) max_delay=$OPTARG ;;
    *)
      _retry_usage
      exit 2
      ;;
    esac
  done
  shift $((OPTIND - 1))
  if [ $# -eq 0 ]; then
    _retry_usage
    exit 2
  fi
  for value in "$attempts" "$timeout" "$delay" "$max_delay"; do
    case $value in
    '' | *[!0-9]*)
      echo "retry: '$value' isn't a whole number" >&2
      _retry_usage
      exit 2
      ;;
    esac
  done
  if [ "$attempts" -lt 1 ]; then
    echo "retry: the command needs at least one attempt" >&2
    exit 2
  fi

  # Without a terminal, the command runs in a process group of its own, so a
  # timeout or a cancellation also stops what it started, such as a package
  # manager under sudo. With a terminal, it stays in the terminal's group,
  # where it can still prompt for a password.
  isolate=false
  if ! { : </dev/tty; } 2>/dev/null; then
    isolate=true
  fi

  command_pid=
  sleeper_pid=
  trap '_retry_cancel; exit 130' INT
  trap '_retry_cancel; exit 143' TERM

  attempt=1
  wait_seconds=$delay
  while :; do
    started=$SECONDS
    if $isolate; then
      set -m
    fi
    "$@" &
    command_pid=$!
    set +m
    if [ "$timeout" -gt 0 ]; then
      # The watchdog learns that the attempt ended when file descriptor 9
      # closes, rather than from a signal: bash 3.2 can lose a signal that
      # arrives while a subshell is starting.
      exec 9> >(_retry_watchdog "$command_pid" "$timeout" "$isolate" "$*" >/dev/null)
    fi
    wait "$command_pid"
    status=$?
    command_pid=
    if [ "$timeout" -gt 0 ]; then
      exec 9>&-
      if [ "$status" -ne 0 ] && [ $((SECONDS - started)) -ge "$timeout" ]; then
        status=124
      fi
    fi

    if [ "$status" -eq 0 ]; then
      exit 0
    fi
    case $status in
    126 | 127)
      _retry_log error "'$*' can't be run (status $status), not retrying"
      exit "$status"
      ;;
    esac
    if [ "$attempt" -ge "$attempts" ]; then
      _retry_log error "'$*' failed with status $status on attempt $attempt of $attempts, giving up"
      exit "$status"
    fi

    if [ "$wait_seconds" -gt "$max_delay" ]; then
      wait_seconds=$max_delay
    fi
    pause=$((wait_seconds + RANDOM % (wait_seconds / 2 + 1)))
    _retry_log warning "'$*' failed with status $status on attempt $attempt of $attempts, retrying in ${pause}s"
    _retry_sleep "$pause"
    attempt=$((attempt + 1))
    wait_seconds=$((wait_seconds * 2))
  done
}

# _retry_watchdog stops the attempt with process ID $1, as a process group if
# $3 is true, once it has run for $2 seconds. It returns as soon as its
# standard input closes, which happens when the attempt ends. $4 names the
# command in the log.
_retry_watchdog() {
  target=$1
  if $3; then
    target=-$1
  fi
  if _retry_closes_within "$2"; then
    return
  fi
  echo "retry: '$4' is still running after ${2}s, stopping it" >&2
  kill -TERM -- "$target" 2>/dev/null
  if _retry_closes_within 10; then
    return
  fi
  kill -KILL -- "$target" 2>/dev/null
}

# _retry_closes_within succeeds if standard input closes within $1 seconds.
# bash 3.2's read returns 1 both at the end of the input and on a timeout, so
# the time it took tells the two apart.
_retry_closes_within() {
  read_started=$SECONDS
  read -r -t "$1" _
  [ $((SECONDS - read_started)) -lt "$1" ]
}

# _retry_sleep sleeps in the background, so that a cancellation can interrupt
# it. The sleeper holds no output, so it can't keep a command substitution
# around the retry open.
_retry_sleep() {
  sleep "$1" >/dev/null 2>&1 &
  sleeper_pid=$!
  wait "$sleeper_pid"
  sleeper_pid=
}

_retry_cancel() {
  if [ -n "$sleeper_pid" ]; then
    kill "$sleeper_pid" 2>/dev/null
  fi
  if [ -n "$command_pid" ]; then
    if $isolate; then
      kill -TERM -- "-$command_pid" 2>/dev/null
    else
      kill -TERM "$command_pid" 2>/dev/null
    fi
  fi
}

# _retry_log prints $2 to stderr, as a GitHub Actions annotation of level $1
# when running there, so a retried download shows up in the run summary.
_retry_log() {
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::$1::retry: $2" >&2
  else
    echo "retry: $2" >&2
  fi
}

_retry_usage() {
  echo "usage: retry [-n attempts] [-t timeout] [-d delay] [-m max-delay] [--] command [args...]" >&2
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  _retry "$@"
fi
