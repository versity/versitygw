#!/bin/bash

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

if [[ -z "$VERSITYGW_TEST_ENV" ]] && [[ $BYPASS_ENV_FILE != "true" ]]; then
  echo "Error:  VERSITYGW_TEST_ENV parameter must be set, or BYPASS_ENV_FILE must be set to true"
  exit 1
fi

# print config for test results info
grep -v ^# "$VERSITYGW_TEST_ENV"

status=0

for cmd in s3api s3 s3cmd mc rest; do
  if ! ./tests/run.sh "$cmd"; then
    status=1
  fi
done

exit $status
