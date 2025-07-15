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

allow_public_access() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  if ! result=$(COMMAND_LOG="$COMMAND_LOG" BUCKET_NAME="$1" BLOCK_PUBLIC_ACLS="FALSE" IGNORE_PUBLIC_ACLS="FALSE" RESTRICT_PUBLIC_BUCKETS="FALSE" OUTPUT_FILE="$TEST_FILE_FOLDER/response.txt" ./tests/rest_scripts/put_public_access_block.sh 2>&1); then
    log 2 "error getting public access block: $result"
    return 1
  fi
  if [ "$result" != "200" ]; then
    log 2 "expected '200', was '$result' ($(cat "$TEST_FILE_FOLDER/response.txt"))"
    return 1
  fi
  return 0
}