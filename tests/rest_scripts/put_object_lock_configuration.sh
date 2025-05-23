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
retention_rule="${RETENTION_RULE:=false}"
# shellcheck disable=SC2153
retention_days="$RETENTION_DAYS"
# shellcheck disable=SC2153
retention_mode="$RETENTION_MODE"
# shellcheck disable=SC2153
retention_years="$RETENTION_YEARS"
# shellcheck disable=SC2153
omit_content_md5="${OMIT_CONTENT_MD5:=false}"


  payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
   <ObjectLockEnabled>Enabled</ObjectLockEnabled>"
if [ "$retention_rule" != "false" ]; then
  payload+="<Rule>
    <DefaultRetention>
      <Days>$retention_days<Days>
      <Mode>$retention_mode</Mode>
      <Years>$retention_years</Years>
    </DefaultRetention>
  </Rule>"
fi
  payload+="</ObjectLockConfiguration>"

payload_hash="$(echo -n "$payload" | sha256sum | awk '{print $1}')"
if [ "$omit_content_md5" == "false" ]; then
  content_md5=$(echo -n "$payload" | openssl dgst -binary -md5 | openssl base64)
fi
current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")

cr_data=("PUT" "/$bucket_name" "object-lock=")
if [ "$omit_content_md5" == "false" ]; then
  cr_data+=("content-md5:$content_md5")
fi
cr_data+=("host:$host")
cr_data+=("x-amz-content-sha256:$payload_hash" "x-amz-date:$current_date_time")
build_canonical_request "${cr_data[@]}"

# shellcheck disable=SC2119
create_canonical_hash_sts_and_signature

curl_command+=(curl -ks -w "\"%{http_code}\"" -X PUT "$AWS_ENDPOINT_URL/$bucket_name?object-lock")
curl_command+=(-H "\"Authorization: AWS4-HMAC-SHA256 Credential=$aws_access_key_id/$year_month_day/$aws_region/s3/aws4_request,SignedHeaders=$param_list,Signature=$signature\"")
curl_command+=("${header_fields[@]}")
curl_command+=(-d "\"${payload//\"/\\\"}\"" -o "$OUTPUT_FILE")
# shellcheck disable=SC2154
eval "${curl_command[*]}" 2>&1
