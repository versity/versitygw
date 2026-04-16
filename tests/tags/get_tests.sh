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

source ./tests/drivers/file.sh
source ./tests/drivers/params.sh

usage() {
  cat >&2 <<'EOF'
Usage:
  tests/tags/get_tests.sh [--any] [--list] [--count] [--run] <tag1,tag2,...>
  tests/tags/get_tests.sh --list-tags <tag>

Options:
  --any         Match any of the provided tags (OR). Default is ALL tags (AND).
  --list        Print matching tests (one per line).
  --count       Print count of matching tests.
  --run         Execute matching tests via bats.
  --list-tags   Print descriptions for tags (from tests/tags/tags.yaml).
  -h, --help    Show this help.

Notes:
  - Requires VERSITYGW_TEST_ENV to be set.
  - Tags are passed as a single comma-separated argument.

Examples:
  VERSITYGW_TEST_ENV=./tests/.env.default tests/tags/get_tests.sh --list ListBuckets
  VERSITYGW_TEST_ENV=./tests/.env.default tests/tags/get_tests.sh --any --count "openssl,ListBuckets"
  tests/tags/get_tests.sh --list-tags ListBuckets
EOF
}

list_tests_by_tags() {
  if ! check_param_count_gt "tag matching mode, comma-separated tags (optional)" 1 $#; then
    return 1
  fi
  mapfile -t files < <(git ls-files 'tests/**/*.sh' 'tests/**/*.bats' 'tests/*.sh' 'tests/*.bats')
  python3 ./tests/tags/get_test_info.py "$1" "$2" "${files[@]}"
}

run_tests() {
  if ! check_param_count_v2 "test lines" 1 $#; then
    return 1
  fi

  if [ -z "$VERSITYGW_TEST_ENV" ]; then
    usage
    echo "VERSITYGW_TEST_ENV must be defined" >&2
    exit 1
  fi

  local i=0 files=() names=() tags=()

  while IFS=$'\t' read -r loc t name || [ -n "$loc" ]; do
    [ -n "${loc:-}" ] || continue
    file="${loc%%:*}"
    files+=("$file")
    tags+=("${t:-}")
    names+=("${name:-}")
    i=$((i+1))
  done <<< "$1"

  if [ "${#files[@]}" -eq 0 ]; then
    echo "no matching tests"
    exit 0
  fi

  for ((j=0;j<${#files[@]};j++)); do
    file="${files[$j]}"
    name="${names[$j]}"
    name_re="$(escape_regex "$name")"
    cmd=("$HOME/bin/bats" -f "$name_re" "$file")
    if ! VERSITYGW_TEST_ENV=$VERSITYGW_TEST_ENV "${cmd[@]}"; then
      echo "error running test"
      exit 1
    fi
  done
}

escape_regex() {
  python3 - "$1" <<'PY'
import re, sys
print(re.escape(sys.argv[1]))
PY
}

list_and_run_tests() {
  if ! check_param_count_gt "matching mode, list flag, count flag, run flag, tags" 4 $#; then
    return 1
  fi
  if [ "$2" -eq 0 ] && [ "$3" -eq 0 ] && [ "$4" -eq 0 ]; then
    usage
    return 1
  fi
  tests=$(list_tests_by_tags "$1" "${@:5}")
  if [ "$2" -eq 1 ]; then
    echo "$tests"
  fi

  if [ "$3" -eq 1 ]; then
    count=$(wc -l <(echo "$tests") | awk '{print $1}')
    echo "$count tests matching tags"
  fi

  if [ "$4" -eq 1 ]; then
    run_tests "$tests"
  fi
  exit 0
}

count_flag=0 list_flag=0 tag_matching_mode="all" list_tags_flag=0 run_flag=0 tag_type="" forwarded_args=()
for arg in "$@"; do
  case "$arg" in
    --count) count_flag=1 ;;
    --list) list_flag=1 ;;
    --any) tag_matching_mode="any" ;;
    -h|--help) usage; exit 0 ;;
    --list-tags) list_tags_flag=1
      shift
      tag_type="$1"
      ;;
    --run) run_flag=1 ;;
    *) forwarded_args+=("$arg") ;;
  esac
done

if [ "$list_tags_flag" -eq 1 ]; then
  if [ "$count_flag" -eq 1 ] || [ "$list_flag" -eq 1 ] || [ "$run_flag" -eq 1 ]; then
    echo "only --list-tags flag should be set when used"
    usage
    exit 1
  fi
  python3 ./tests/tags/list_tags.py "$tag_type"
  exit 0
fi

list_and_run_tests "$tag_matching_mode" "$list_flag" "$count_flag" "$run_flag" "${forwarded_args[@]}"

