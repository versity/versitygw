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

source ./tests/rest_scripts/rest.sh
source ./tests/util/util_file.sh

# Fields

# shellcheck disable=SC2153
data_file="$DATA_FILE"
# shellcheck disable=SC2153
bucket_name="$BUCKET_NAME"
# shellcheck disable=SC2153
key="$OBJECT_KEY"
# shellcheck disable=SC2153
omit_content_length="${OMIT_CONTENT_LENGTH:=false}"
# shellcheck disable=SC2153
command_file="${COMMAND_FILE:=command.txt}"

if ! file_size=$(get_file_size "$data_file"); then
  log_rest 2 "error getting file size"
  exit 1
fi

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
payload_hash="$(sha256sum "$data_file" | awk '{print $1}')"

cr_data=("PUT" "/$bucket_name/$key" "")
cr_data+=("host:$host")
cr_data+=("x-amz-content-sha256:$payload_hash" "x-amz-date:$current_date_time")
build_canonical_request "${cr_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

command="PUT /$bucket_name/$key HTTP/1.1\r
Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\r
"
if [ "$omit_content_length" == "false" ]; then
  command+="Content-Length: $file_size
"
fi
for header_field in "${cr_data[@]}"; do
  if [[ "$header_field" =~ ^.+:.+$ ]]; then
    command+="$header_field\r
"
  fi
done
command+="\r\n"
echo -en "$command" > "$command_file"
dd if="$data_file" bs="$file_size" count=1 >> "$command_file"
