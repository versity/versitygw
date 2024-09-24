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

delete_object_tagging() {
  record_command "delete-object-tagging" "client:$1"
  if [[ $# -ne 3 ]]; then
    echo "delete object tagging command missing command type, bucket, key"
    return 1
  fi
  delete_result=0
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api delete-object-tagging --bucket "$2" --key "$3" 2>&1) || delete_result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure tag remove "$MC_ALIAS/$2/$3") || delete_result=$?
  elif [ "$1" == 'rest' ]; then
    delete_object_tagging_rest "$2" "$3" || delete_result=$?
  else
    echo "delete-object-tagging command not implemented for '$1'"
    return 1
  fi
  if [[ $delete_result -ne 0 ]]; then
    echo "error deleting object tagging: $error"
    return 1
  fi
  return 0
}

delete_object_tagging_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'delete_object_tagging' requires bucket, key"
    return 1
  fi

  generate_hash_for_payload ""

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="DELETE
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
  reply=$(curl -ks -w "%{http_code}" -X DELETE "$header://$aws_endpoint_url_address/$1/$2?tagging" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: $payload_hash" \
    -H "x-amz-date: $current_date_time" \
    -d "$tagging" -o "$TEST_FILE_FOLDER"/delete_tagging_error.txt 2>&1)
  log 5 "reply status code: $reply"
  if [[ "$reply" != "204" ]]; then
    log 2 "reply error: $reply"
    log 2 "put object tagging command returned error: $(cat "$TEST_FILE_FOLDER"/delete_tagging_error.txt)"
    return 1
  fi
  return 0
}
