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

payload=""
# shellcheck disable=SC2153
aws_access_key_id="$AWS_ACCESS_KEY_ID"
# shellcheck disable=SC2153
aws_secret_access_key="$AWS_SECRET_ACCESS_KEY"
get_host
get_aws_region

# Step 1:  generate payload hash

payload_hash="$(echo -n "$payload" | sha256sum | awk '{print $1}')"

# Step 2:  generate canonical hash

current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

canonical_request="GET
/

host:$host
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
$payload_hash"

canonical_request_hash="$(echo -n "$canonical_request" | openssl dgst -sha256 | awk '{print $2}')"

# Step 3:  create STS data string

year_month_day="$(echo "$current_date_time" | cut -c1-8)"

sts_data="AWS4-HMAC-SHA256
$current_date_time
$year_month_day/$aws_region/s3/aws4_request
$canonical_request_hash"

# Step 4:  generate signature

date_key=$(echo -n "$year_month_day" | openssl dgst -sha256 -mac HMAC -macopt key:"AWS4${aws_secret_access_key}" | awk '{print $2}')
date_region_key=$(echo -n "$aws_region" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_key" | awk '{print $2}')
date_region_service_key=$(echo -n "s3" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_region_key" | awk '{print $2}')
signing_key=$(echo -n "aws4_request" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$date_region_service_key" | awk '{print $2}')
signature=$(echo -n "$sts_data" | openssl dgst -sha256 \
                 -mac HMAC \
                 -macopt hexkey:"$signing_key" | awk '{print $2}')

# Step 5:  send curl command

curl -ks "https://$host/" \
       -H "Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
       -H "x-amz-content-sha256: $payload_hash" \
       -H "x-amz-date: $current_date_time"