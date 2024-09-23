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

put_object_retention() {
  record_command "put-object-retention" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "'put object retention' command requires bucket, key, retention mode, retention date"
    return 1
  fi
  error=$(aws --no-verify-ssl s3api put-object-retention --bucket "$1" --key "$2" --retention "{\"Mode\": \"$3\", \"RetainUntilDate\": \"$4\"}" 2>&1) || local put_result=$?
  if [[ $put_result -ne 0 ]]; then
    log 2 "error putting object retention:  $error"
    return 1
  fi
  return 0
}

put_object_retention_rest() {
  if [ $# -ne 4 ]; then
    log 2 "'put_object_retention_rest' requires bucket, key, retention mode, retention date"
    return 1
  fi

  retention="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
  <Mode>$3</Mode>
  <RetainUntilDate>$4</RetainUntilDate>
</Retention>"

  log 5 "retention payload: $retention"
  generate_hash_for_payload "$retention"

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  content_md5=$(echo -n "$retention" | openssl dgst -binary -md5 | openssl base64)
  # shellcheck disable=SC2154
  canonical_request="PUT
/$1/$2
retention=
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
  reply=$(curl -ks -w "%{http_code}" -X PUT "$header://$aws_endpoint_url_address/$1/$2?retention" \
    -H "Content-MD5: $content_md5" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: $payload_hash" \
    -H "x-amz-date: $current_date_time" \
    -d "$retention" -o "$TEST_FILE_FOLDER"/put_object_retention_error.txt 2>&1)
  log 5 "reply status code: $reply"
  if [[ "$reply" != "200" ]]; then
    log 2 "reply error: $reply"
    log 2 "put object retention command returned error: $(cat "$TEST_FILE_FOLDER"/put_object_retention_error.txt)"
    return 1
  fi
  return 0
}
