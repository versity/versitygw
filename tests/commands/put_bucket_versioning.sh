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

put_bucket_versioning() {
  record_command "put-bucket-versioning" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "put bucket versioning command requires command type, bucket name, 'Enabled' or 'Suspended'"
    return 1
  fi
  local put_result=0
  if [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api put-bucket-versioning --bucket "$2" --versioning-configuration "{ \"Status\": \"$3\"}" 2>&1) || put_result=$?
  fi
  if [[ $put_result -ne 0 ]]; then
    log 2 "error putting bucket versioning: $error"
    return 1
  fi
  return 0
}

put_bucket_versioning_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'put_bucket_versioning_rest' requires bucket, 'Enabled' or 'Suspended'"
    return 1
  fi

  versioning="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
  <Status>$2</Status>
</VersioningConfiguration>"

  generate_hash_for_payload "$versioning"

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  content_md5=$(echo -n "$versioning" | openssl dgst -binary -md5 | openssl base64)
  # shellcheck disable=SC2154
  canonical_request="PUT
/$1
versioning=
content-md5:$content_md5
host:$aws_endpoint_url_address
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

content-md5;host;x-amz-content-sha256;x-amz-date
$payload_hash"

  if ! generate_sts_string "$current_date_time" "$canonical_request"; then
    log 2 "error generating sts string"
    return 1
  fi
  get_signature

  # shellcheck disable=SC2154
  reply=$(send_command curl -ks -w "%{http_code}" -X PUT "$header://$aws_endpoint_url_address/$1?versioning" \
    -H "Content-MD5: $content_md5" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: $payload_hash" \
    -H "x-amz-date: $current_date_time" \
    -d "$versioning" -o "$TEST_FILE_FOLDER"/put_versioning_error.txt 2>&1)
  log 5 "reply status code: $reply"
  if [[ "$reply" != "200" ]]; then
    log 2 "reply error: $reply"
    log 2 "put bucket versioning command returned error: $(cat "$TEST_FILE_FOLDER"/put_versioning_error.txt)"
    return 1
  fi
  return 0
}