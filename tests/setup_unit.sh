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

source ./tests/setup_common.sh

export UNIT_TEST=true

setup() {
  if ! setup_env; then
    echo "error with env setup" >&2
    return 1
  fi
  return 0
}

teardown() {
  if ! teardown_logs; then
    echo "log teardown errors" >&2
    return 1
  fi
  return 0
}