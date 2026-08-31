#!/usr/bin/env bats

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

load ./bats-support/load
load ./bats-assert/load

source ./tests/commands/list_buckets.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/list_buckets/list_buckets_rest.sh
source ./tests/logger.sh
source ./tests/setup.sh

setup() {
  if ! setup_env; then
    log 1 "error setting up env"
    return 1
  fi
  if ! BACKEND=s3ToPosix setup_versitygw; then
    log 1 "error setting up s3->posix versitygw config"
    return 1
  fi
  return 0
}

teardown() {
  BACKEND=s3ToPosix teardown_common
}

@test "ListBuckets - s3 -> posix" {
  skip "https://github.com/versity/versitygw/issues/2309"

  local bucket_name

  run setup_bucket_v3 "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run list_check_buckets_rest "$bucket_name"
  assert_success
}