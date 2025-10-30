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

parse_object_tags_s3api() {
  if ! tag_set_key=$(echo "$tags" | jq -r '.TagSet[0].Key' 2>&1); then
    log 2 "error retrieving tag key: $tag_set_key"
    return 1
  fi
  if ! tag_set_value=$(echo "$tags" | jq -r '.TagSet[0].Value' 2>&1); then
    log 2 "error retrieving tag value: $tag_set_value"
    return 1
  fi
  return 0
}
