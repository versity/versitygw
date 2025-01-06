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

source ./tests/setup.sh
source ./tests/util/util_object.sh

if ! base_setup; then
  log 2 "error starting versity to set up static buckets"
  exit 1
fi
if ! delete_bucket_recursive "s3api" "$BUCKET_ONE_NAME"; then
  log 2 "error deleting static bucket one"
elif ! delete_bucket_recursive "s3api" "$BUCKET_TWO_NAME"; then
  log 2 "error deleting static bucket two"
else
  log 4 "buckets deleted successfully"
fi
if ! stop_versity; then
  log 2 "error stopping versity"
fi