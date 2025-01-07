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

get_object_tagging() {
  record_command "get-object-tagging" "client:$1"
  if [ $# -ne 3 ]; then
    log 2 "get object tag command missing command type, bucket, and/or key"
    return 1
  fi
  local result
  if [[ $1 == 's3api' ]]; then
    tags=$(send_command aws --no-verify-ssl s3api get-object-tagging --bucket "$2" --key "$3" 2>&1) || result=$?
  elif [[ "$1" == 'mc' ]]; then
    tags=$(send_command mc --insecure tag list "$MC_ALIAS"/"$2"/"$3" 2>&1) || result=$?
  elif [ "$1" == 'rest' ]; then
    get_object_tagging_rest "$2" "$3" || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    if [[ "$tags" == *"NoSuchTagSet"* ]] || [[ "$tags" == *"No tags found"* ]]; then
      tags=
    else
      log 2 "error getting object tags: $tags"
      return 1
    fi
  else
    log 5 "$tags"
    tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  fi
  export tags
}

get_object_tagging_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'get_object_tagging' requires bucket, key"
    return 1
  fi

  generate_hash_for_payload ""

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="GET
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
  reply=$(send_command curl -ks -w "%{http_code}" "$header://$aws_endpoint_url_address/$1/$2?tagging" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: $payload_hash" \
    -H "x-amz-date: $current_date_time" \
    -o "$TEST_FILE_FOLDER"/object_tags.txt 2>&1)
  log 5 "reply status code: $reply"
  if [[ "$reply" != "200" ]]; then
    if [ "$reply" == "404" ]; then
      return 1
    fi
    log 2 "reply error: $reply"
    log 2 "get object tagging command returned error: $(cat "$TEST_FILE_FOLDER"/object_tags.txt)"
    return 2
  fi
  log 5 "object tags:  $(cat "$TEST_FILE_FOLDER"/object_tags.txt)"
  return 0
}