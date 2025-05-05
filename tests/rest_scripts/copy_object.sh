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

# Fields

# shellcheck disable=SC2153
bucket_name="$BUCKET_NAME"
# shellcheck disable=SC2153
key="$OBJECT_KEY"
# shellcheck disable=SC2153
copy_source="$COPY_SOURCE"
# for testing only
# shellcheck disable=SC2153
data_file="$DATA_FILE"

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

cr_data=("PUT" "/$bucket_name/$key" "")
cr_data+=("host:$host" "x-amz-content-sha256:UNSIGNED-PAYLOAD")
cr_data+=("x-amz-copy-source:$copy_source")
cr_data+=("x-amz-date:$current_date_time")
build_canonical_request "${cr_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"" -X PUT "$AWS_ENDPOINT_URL/$bucket_name/$key")
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
curl_command+=("${header_fields[@]}")
curl_command+=(-o "$OUTPUT_FILE")
if [ "$data_file" != "" ]; then
  curl_command+=(-T "$data_file")
fi
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
