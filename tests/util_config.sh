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

setup_two_buckets() {
  setup_bucket "$BUCKET_ONE_NAME" || local setup_result_one=$?
  if [[ $setup_result_one -eq 0 ]]; then
    return 1
  fi
  setup_bucket "$BUCKET_TWO_NAME" || local setup_result_two=$?
  if [[ $setup_result_two -eq 0 ]]; then
    return 1
  fi
  return 0
}