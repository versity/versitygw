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

source ./tests/commands/command.sh

# shellcheck disable=SC2153,SC2034
aws_access_key_id="$AWS_ACCESS_KEY_ID"
# shellcheck disable=SC2153,SC2034
aws_secret_access_key="$AWS_SECRET_ACCESS_KEY"

if [ -z "$AWS_ENDPOINT_URL" ]; then
  host="localhost:7070"
else
  # shellcheck disable=SC2034
  host="$(echo "$AWS_ENDPOINT_URL" | awk -F'//' '{print $2}')"
fi

if [ -z "$AWS_REGION" ]; then
  aws_region="us-east-1"
else
  # shellcheck disable=SC2034
  aws_region="$AWS_REGION"
fi

add_command_recording_if_enabled() {
  if [ -n "$COMMAND_LOG" ]; then
    curl_command+=(send_command)
  fi
}
