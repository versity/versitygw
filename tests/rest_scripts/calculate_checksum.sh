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

source ./tests/rest_scripts/rest.sh

calculate_checksum_python() {
  if [ "$#" -ne 2 ]; then
    log 2 "'calculate_checksum_python' requires checksum type, data file"
    return 1
  fi
  if ! DEACTIVATE=false source ./tests/rest_scripts/init_python_env.sh; then
    log_rest 2 "error initializing python environment"
    return 1
  fi
  if ! checksum_decimal=$(python3 ./tests/rest_scripts/calculate_checksum.py "$1" "$2" 2>&1); then
    log_rest 2 "error calculating checksum: $checksum_decimal"
    return 1
  fi
  log 5 "decimal checksum: $checksum_decimal"
  if ! deactivate 1>/dev/null; then
    log_rest 2 "error deactivating virtual environment"
    return 1
  fi
  if [ "$CHECKSUM_TYPE" == "crc64nvme" ]; then
    hex_format="%016x"
  else
    hex_format="%08x"
  fi
  # shellcheck disable=SC2059
  checksum=$(printf "$hex_format" "$checksum_decimal" | xxd -r -p | base64)
  echo "$checksum"
}

case "$CHECKSUM_TYPE" in
"crc32c"|"CRC32C")
  if ! checksum=$(calculate_checksum_python "crc32c" "$DATA_FILE" 2>&1); then
    log_rest 2 "error getting checksum: $checksum"
    exit 1
  fi
  ;;
"crc64nvme"|"CRC64NVME")
  if ! checksum=$(calculate_checksum_python "crc64nvme" "$DATA_FILE" 2>&1); then
    log 2 "error calculating checksum: $checksum"
    exit 1
  fi
  ;;
"sha256"|"SHA256")
  checksum="$(sha256sum "$DATA_FILE" | awk '{print $1}' | xxd -r -p | base64)"
  ;;
"sha1"|"SHA1")
  checksum="$(sha1sum "$DATA_FILE" | awk '{print $1}' | xxd -r -p | base64)"
  ;;
"crc32"|"CRC32")
  checksum="$(gzip -c -1 "$DATA_FILE" | tail -c8 | od -t x4 -N 4 -A n | awk '{print $1}' | xxd -r -p | base64)"
  ;;
*)
  log_rest 2 "invalid checksum type: '$CHECKSUM_TYPE'"
  exit 1
  ;;
esac
echo "$checksum"
