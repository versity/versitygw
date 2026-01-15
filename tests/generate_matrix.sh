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

# generate github-actions matrix for system.yml

source ./tests/drivers/params.sh

set -euo pipefail

files=()
iam_types=()
regions=()
idx=0

check_for_and_load_test_file_and_params() {
  if ! check_param_count_v2 "file name" 1 $#; then
    exit 1
  fi
  if grep -q '@test' "$1"; then
    if [ $(( idx % 8 )) -eq 0 ]; then
      iam="s3"
    else
      iam="folder"
    fi
    iam_types+=("$iam")
    if [ $(( idx % 4 )) -eq 0 ]; then
      region="us-west-1"
    else
      region="us-east-1"
    fi
    regions+=("$region")
    files+=("$1")
    idx=$((idx + 1))
  fi
}

while IFS= read -r f; do
  check_for_and_load_test_file_and_params "$f"
done < <(find tests -name 'test_*.sh' | sort)

files_json_arr=$(printf '%s\n' "${files[@]}"   | jq -R . | jq -s .)
regions_json_arr=$(printf '%s\n' "${regions[@]}" | jq -R . | jq -s .)
iam_types_json_arr=$(printf '%s\n' "${iam_types[@]}" | jq -R . | jq -s .)

matrix_json=$(
  jq -n \
    --argjson files   "$files_json_arr" \
    --argjson regions "$regions_json_arr" \
    --argjson iam_types "$iam_types_json_arr" \
    '
    {
      include:
        [ range(0; ($files|length)) as $i
          | [
              {
                desc: ("Run " + $files[$i] + ", non-static, " + $regions[$i] + " region, " + $iam_types[$i] + " IAM type"),
                RUN_SET: $files[$i],
                AWS_REGION: $regions[$i],
                IAM_TYPE: $iam_types[$i],
                BACKEND: "posix",
                RECREATE_BUCKETS: "true",
                DELETE_BUCKETS_AFTER_TEST: "true"
              },
              {
                desc: ("Run " + $files[$i] + ", static, " + $regions[$i] + " region, " + $iam_types[$i] + " IAM type"),
                RUN_SET: $files[$i],
                AWS_REGION: $regions[$i],
                IAM_TYPE: $iam_types[$i],
                BACKEND: "posix",
                RECREATE_BUCKETS: "false",
                DELETE_BUCKETS_AFTER_TEST: "false"
              }
            ]
        ] | add
    }
    '
)

echo "$matrix_json"
