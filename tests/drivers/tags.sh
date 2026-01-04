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

check_tags_empty() {
  if ! check_param_count_v2 "command type" 1 $#; then
    return 1
  fi
  if [ "$1" == 'aws' ] || [ "$1" == 's3api' ]; then
    # shellcheck disable=SC2154
    if [[ $tags == "" ]]; then
      return 0
    fi
    tag_set=$(echo "$tags" | jq '.TagSet')
    if [[ $tag_set != "[]" ]]; then
      log 2 "error:  tags not empty: $tags"
      return 1
    fi
  else
    if [[ $tags != "" ]] && [[ $tags != *"No tags found"* ]]; then
      log 2 "Error:  tags not empty: $tags"
      return 1
    fi
  fi
  return 0
}
