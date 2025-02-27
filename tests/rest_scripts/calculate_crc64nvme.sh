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

if ! DEACTIVATE=false source ./tests/rest_scripts/init_python_env.sh; then
  log_rest 2 "error initializing python environment"
  exit 1
fi
if ! checksum_decimal=$(python3 -c "
import sys
from awscrt import checksums

with open(sys.argv[1], 'rb') as f:
  print(checksums.crc64nvme(f.read()))" "$DATA_FILE" 2>&1); then
  log_rest 2 "error calculating checksum: $checksum_decimal"
  exit 1
fi
log 5 "decimal checksum: $checksum_decimal"
if ! deactivate 1>/dev/null; then
  log_rest 2 "error deactivating virtual environment"
  exit 1
fi
checksum_hash=$(printf "%016x" "$checksum_decimal" | xxd -r -p | base64)
echo "$checksum_hash"