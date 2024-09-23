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

get_host() {
  if [ -z "$HOST" ]; then
    host="localhost:7070"
    return
  fi
  # shellcheck disable=SC2034
  host="$HOST"
}

get_aws_region() {
  if [ -z "$AWS_REGION" ]; then
    aws_region="us-east-1"
    return
  fi
  # shellcheck disable=SC2034
  aws_region="$AWS_REGION"
}
