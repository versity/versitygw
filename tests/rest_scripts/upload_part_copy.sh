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

# shellcheck disable=SC2153
bucket_name="$BUCKET_NAME"
# shellcheck disable=SC2153
key="$OBJECT_KEY"
# shellcheck disable=SC2153
part_number="$PART_NUMBER"
# shellcheck disable=SC2153
upload_id="$UPLOAD_ID"
# shellcheck disable=SC2153
part_location=$PART_LOCATION

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
# shellcheck disable=SC2034
header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
# shellcheck disable=SC2154
canonical_request="PUT
/$bucket_name/$key
partNumber=$part_number&uploadId=$upload_id
host:$aws_endpoint_url_address
x-amz-content-sha256:UNSIGNED-PAYLOAD
x-amz-copy-source:$part_location
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-copy-source;x-amz-date
UNSIGNED-PAYLOAD"

create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"" -X PUT "\"$AWS_ENDPOINT_URL/$bucket_name/$key?partNumber=$part_number&uploadId=$upload_id\""
-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-copy-source;x-amz-date,Signature=$signature\""
-H "\"x-amz-content-sha256: UNSIGNED-PAYLOAD\""
-H "\"x-amz-copy-source: $part_location\""
-H "\"x-amz-date: $current_date_time\""
-o "\"$OUTPUT_FILE\"")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1