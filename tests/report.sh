#!/usr/bin/env bash

# Copyright 2024 Versity Software
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

source ./tests/drivers/params.sh

get_curl_method() {
  if ! check_param_count_v2 "command string" 1 $#; then
    return 1
  fi
  local method
  if [[ "$1" =~ (^|[[:space:]])-([^-[:space:]]*)I([^-[:space:]]*) ]]; then
    method="HEAD"
  elif [[ "$1" =~ (^|[[:space:]])-X[[:space:]]*([^[:space:]]+) ]]; then
    method="${BASH_REMATCH[2]}"
  else
    method="GET"
  fi
  echo "$method"
}

parse_path_and_get_route() {
  if ! check_param_count_v2 "string" 1 $#; then
    return 1
  fi

  local url path
  url="$(echo "$1" | grep -oE 'https?://[^" ]+' | head -n 1)"

  # Only accept http/https URLs with a path
  if [ -z "$url" ]; then
    echo "UNKNOWN"
    return 0
  fi

  # Strip protocol + host + port
  path="$(echo "$url" | sed -E 's|https?://[^/]+||')"

  # Normalize: remove leading/trailing slashes
  path="${path#/}"
  path="${path%/}"

  if ! get_route "$path"; then
    log 2 "error getting route"
    return 1
  fi
  return 0
}

get_route() {
  if ! check_param_count_v2 "string" 1 $#; then
    return 1
  fi

  if [ "$1" == '/' ]; then
    echo "MAIN"
    return 0
  fi

  # Split path on '/'
  local route_parts
  IFS='/' read -r -a route_parts <<< "$1"

  if [[ -z "$1" ]]; then
    echo "MAIN"
  elif [[ "${#route_parts[@]}" -eq 1 ]]; then
    echo "BUCKET"
  else
    echo "OBJECT"
  fi
  return 0
}

get_query() {
  # Extract query string (everything after '?')
  local query
  query="${1#*\?}"
  # No query present
  if [[ "$query" == "$1" ]]; then
    echo ""
    return 0
  fi

  # Remove fragment if present
  query="${query%%#*}"

  local query_keys=()
  while [[ $query ]]; do
    key="${query%%=*}" # Extract key
    query_keys+=("$key")

    # If no more keys
    if [[ "$query" != *"&"* ]]; then
      break
    fi

    query="${query#*&}" # Remove extracted part from query
  done

  echo "${query_keys[*]}"
}

check_for_copy_source() {
  if ! check_param_count_v2 "'OPENSSL' or 'CURL', string or file" 2 $#; then
    return 2
  fi
  if [ "$1" == "CURL" ]; then
    if [[ "$2" == *"x-amz-copy-source"* ]]; then
      return 0
    fi
    return 1
  elif [ "$1" == "OPENSSL" ]; then
    if grep -qi 'x-amz-copy-source' "$2"; then
      return 0
    fi
    return 1
  fi
  log 2 "invalid type param: $1"
  return 2
}

parse_path_and_get_query() {
  if ! check_param_count_v2 "string" 1 $#; then
    return 1
  fi

  local url
  url="$(echo "$1" | grep -oE 'https?://[^" ]+' | head -n 1)"

  # Must look like a URL
  if [ -z "$url" ]; then
    echo ""
    return 0
  fi

  get_query "$url"
}

parse_curl_rest_command() {
  if ! check_param_count_v2 "command string" 1 $#; then
    return 1
  fi
  local method route query
  if ! method=$(get_curl_method "$1" 2>&1); then
    echo "error retrieving method: $method"
    return 1
  fi
  if ! route=$(parse_path_and_get_route "$1" 2>&1); then
    echo "error retrieving route: $route"
    return 1
  fi
  if ! query=$(parse_path_and_get_query "$1" 2>&1); then
    echo "error retrieving query: $query"
    return 1
  fi
  output_string="$method $route $query"
  if [[ "$output_string" == "PUT OBJECT"* ]] && check_for_copy_source "CURL" "$1"; then
    output_string+=" x-amz-copy-source"
  fi
  log 5 "output string: $output_string"
  echo "$output_string"
  return 0
}

get_openssl_method_route_queries() {
  if ! check_param_count_v2 "command file" 1 $#; then
    return 1
  fi

  local method route_string route query

  method=$(awk 'NR==1{print $1}' "$1")
  route_string=$(awk 'NR==1{print $2}' "$1")
  route=$(get_route "$route_string")
  query=$(get_query "$route_string")

  echo "$method $route $query"
  return 0
}

write_to_coverage_log() {
  if ! check_param_count_v2 "string" 1 $#; then
    return 1
  fi
  echo "$1" >> "$COVERAGE_LOG"
  sort "$COVERAGE_LOG" | uniq > "${COVERAGE_LOG}.tmp"
  mv "${COVERAGE_LOG}.tmp" "$COVERAGE_LOG"
}

record_openssl_command() {
  if [ -z "$COVERAGE_LOG" ]; then
      return 0
    fi
  if ! check_param_count_v2 "command file" 1 $#; then
    return 1
  fi
  if ! command_info=$(get_openssl_method_route_queries "$1" 2>&1); then
    log 2 "error getting command info: $command_info"
    return 1
  fi
  if [[ "$command_info" == "PUT OBJECT"* ]] && check_for_copy_source "OPENSSL" "$1"; then
    command_info+=" x-amz-copy-source"
  fi
  if ! write_to_coverage_log "$command_info"; then
    log 2 "error writing to coverage log"
    return 1
  fi
  return 0
}

parse_command_info() {
  if ! check_param_count_v2 "command string" 1 $#; then
    return 1
  fi
  if [[ "$1" == *"curl "* ]]; then
    if ! command_info=$(parse_curl_rest_command "$1" 2>&1); then
      echo "error parsing rest command: $command_info"
      return 1
    fi
  else
    command_info="OTHER"
  fi
}

record_command_v2() {
  if [ -z "$COVERAGE_LOG" ]; then
    log 5 "no coverage log set"
    return 0
  fi
  if ! check_param_count_v2 "command string" 1 $#; then
    return 1
  fi
  if ! parse_command_info "$1"; then
    log 2 "error parsing command info"
    return 1
  fi
  if [ "$command_info" == "OTHER" ]; then
    return 0
  fi
  if ! write_to_coverage_log "$command_info"; then
    log 2 "error writing to coverage log"
    return 1
  fi
}
