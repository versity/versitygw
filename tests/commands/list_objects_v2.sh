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

# list objects in bucket, v2
# param:  bucket
# export objects on success, return 1 for failure
list_objects_v2() {
  if [ $# -ne 1 ]; then
    log 2 "list objects command missing bucket and/or path"
    return 1
  fi
  record_command "list-objects-v2 client:s3api"
  objects=$(send_command aws --no-verify-ssl s3api list-objects-v2 --bucket "$1") || local result=$?
  if [[ $result -ne 0 ]]; then
    log 2 "error listing objects: $objects"
    return 1
  fi
}