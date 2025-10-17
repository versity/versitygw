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

parse_object_tags_rest() {
  if ! tag_set_key=$(xmllint --xpath '//*[local-name()="Key"]/text()' "$TEST_FILE_FOLDER/object_tags.txt" 2>&1); then
    log 2 "error getting key: $tag_set_key"
    return 1
  fi
  if ! tag_set_value=$(xmllint --xpath '//*[local-name()="Value"]/text()' "$TEST_FILE_FOLDER/object_tags.txt" 2>&1); then
    log 2 "error getting value: $value"
    return 1
  fi
  return 0
}
