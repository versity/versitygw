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

put_object_tagging() {
  if [ $# -ne 5 ]; then
    log 2 "'put-object-tagging' command missing command type, bucket, object name, file, key, and/or value"
    return 1
  fi
  local error
  local result
  record_command "put-object-tagging" "client:$1"
  if [[ $1 == 's3api' ]]; then
    error=$(send_command aws --no-verify-ssl s3api put-object-tagging --bucket "$2" --key "$3" --tagging "TagSet=[{Key=$4,Value=$5}]" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(send_command mc --insecure tag set "$MC_ALIAS"/"$2"/"$3" "$4=$5" 2>&1) || result=$?
  elif [[ $1 == 'rest' ]]; then
    put_object_tagging_rest "$2" "$3" "$4" "$5" || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    log 2 "Error adding object tag: $error"
    return 1
  fi
  return 0
}

put_object_tagging_rest() {
  if [ $# -ne 4 ]; then
    log 2 "'put_object_tagging' requires bucket, key, tag key, tag value"
    return 1
  fi

  tagging="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
  <TagSet>
    <Tag>
      <Key>$3</Key>
      <Value>$4</Value>
    </Tag>
  </TagSet>
</Tagging>"

  generate_hash_for_payload "$tagging"

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="PUT
/$1/$2
tagging=
host:$aws_endpoint_url_address
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
$payload_hash"

  if ! generate_sts_string "$current_date_time" "$canonical_request"; then
    log 2 "error generating sts string"
    return 1
  fi
  get_signature
  # shellcheck disable=SC2154
  reply=$(send_command curl -ks -w "%{http_code}" -X PUT "$header://$aws_endpoint_url_address/$1/$2?tagging" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: $payload_hash" \
    -H "x-amz-date: $current_date_time" \
    -d "$tagging" -o "$TEST_FILE_FOLDER"/put_tagging_error.txt 2>&1)
  log 5 "reply status code: $reply"
  if [[ "$reply" != "200" ]]; then
    log 2 "reply error: $reply"
    log 2 "put object tagging command returned error: $(cat "$TEST_FILE_FOLDER"/put_tagging_error.txt)"
    return 1
  fi
  return 0
}
