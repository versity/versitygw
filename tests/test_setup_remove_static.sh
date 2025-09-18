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

source ./tests/logger.sh

if [ -z "$VERSITYGW_TEST_ENV" ]; then
  echo "VERSITYGW_TEST_ENV variable missing"
  return 1
fi
# shellcheck disable=SC1090
source "$VERSITYGW_TEST_ENV"
if [ "$RECREATE_BUCKETS" != "true" ] || [ "$DELETE_BUCKETS_AFTER_TEST" != "true" ]; then
  echo "for this test 'RECREATE_BUCKETS' and 'DELETE_BUCKETS_AFTER_TEST' must be set to true"
  exit 1
fi
# try to remove buckets if already there, don't worry if they're not
./tests/remove_static.sh
echo "AFTER FIRST REMOVAL"
if ! result=$(./tests/setup_static.sh 2>&1); then
  echo "error setting up buckets: $result"
  exit 1
fi
echo "RESULT:  $result"
if [[ "$result" != *"bucket '$BUCKET_ONE_NAME' successfully created"* ]]; then
  echo "error creating bucket '$BUCKET_ONE_NAME'"
  exit 1
fi
if [[ "$result" != *"bucket '$BUCKET_TWO_NAME' successfully created"* ]]; then
  echo "error creating bucket '$BUCKET_TWO_NAME'"
  exit 1
fi
if ! result=$(./tests/remove_static.sh 2>&1); then
  echo "error removing buckets: $result"
  exit 1
fi
if [[ "$result" != *"bucket '$BUCKET_ONE_NAME' successfully deleted"* ]]; then
  echo "error deleting bucket '$BUCKET_ONE_NAME'"
  exit 1
fi
if [[ "$result" != *"bucket '$BUCKET_TWO_NAME' successfully deleted"* ]]; then
  echo "error deleting bucket '$BUCKET_TWO_NAME'"
  exit 1
fi
exit 0