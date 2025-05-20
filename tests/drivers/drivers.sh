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

check_param_count() {
  if [ $# -ne 4 ]; then
    log 2 "'check_param_count' requires function name, params list, expected, actual"
    return 1
  fi
  if [ "$3" -ne "$4" ]; then
    log 2 "function $1 requires $2"
    return 1
  fi
  return 0
}

check_param_count_gt() {
  if [ $# -ne 4 ]; then
    log 2 "'check_param_count_gt' requires function name, params list, expected minimum, actual"
    return 1
  fi
  if [ "$3" -gt "$4" ]; then
    log 2 "function $1 requires $2"
    return 1
  fi
  return 0
}
