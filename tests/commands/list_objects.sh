#!/usr/bin/env bash

source ./tests/util_list_objects.sh
source ./tests/commands/command.sh

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

# args: client, bucket name
# return 0 if able to list, 1 if not
list_objects() {
  log 6 "list_objects"
  record_command "list-objects" "client:$1"
  if [ $# -ne 2 ]; then
    log 2 "'list_objects' command requires client, bucket"
    return 1
  fi

  local output
  local result=0
  if [[ $1 == "aws" ]] || [[ $1 == 's3' ]]; then
    output=$(send_command aws --no-verify-ssl s3 ls s3://"$2" 2>&1) || result=$?
  elif [[ $1 == 's3api' ]]; then
    list_objects_s3api "$2" || result=$?
    return $result
  elif [[ $1 == 's3cmd' ]]; then
    output=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    output=$(send_command mc --insecure ls "$MC_ALIAS"/"$2" 2>&1) || result=$?
  elif [[ $1 == 'rest' ]]; then
    list_objects_rest "$2" || result=$?
    return $result
  else
    fail "invalid command type $1"
    return 1
  fi
  # shellcheck disable=SC2154
  assert_success "error listing objects: $output"

  object_array=()
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      object_name=$(echo "$line" | awk '{print $NF}')
      object_array+=("$object_name")
    fi
  done <<< "$output"

  export object_array
}

# args: bucket name
# fail if unable to list
list_objects_s3api() {
  log 6 "list_objects_s3api"
  if [ $# -ne 1 ]; then
    log 2 "'list_objects_s3api' requires bucket"
    return 1
  fi
  if ! output=$(send_command aws --no-verify-ssl s3api list-objects --bucket "$1" 2>&1); then
    log 2 "error listing objects: $output"
    return 1
  fi

  log 5 "list_objects_s3api: raw data returned: $output"
  modified_output=$(echo "$output" | grep -v "InsecureRequestWarning")

  object_array=()
  log 5 "modified output: $modified_output"
  if echo "$modified_output" | jq -e 'has("Contents")'; then
    contents=$(echo "$modified_output" | jq -r '.Contents[]')
    log 5 "contents: $contents"
    keys=$(echo "$contents" | jq -r '.Key')
    IFS=$'\n' read -rd '' -a object_array <<<"$keys"
  fi
  return 0
}

# list objects in bucket, v1
# param:  bucket
# export objects on success, return 1 for failure
list_objects_s3api_v1() {
  if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "list objects command requires bucket, (optional) delimiter"
    return 1
  fi
  if [ "$2" == "" ]; then
    objects=$(send_command aws --no-verify-ssl s3api list-objects --bucket "$1") || local result=$?
  else
    objects=$(send_command aws --no-verify-ssl s3api list-objects --bucket "$1" --delimiter "$2") || local result=$?
  fi
  if [[ $result -ne 0 ]]; then
    echo "error listing objects: $objects"
    return 1
  fi
  export objects
}

list_objects_with_prefix() {
  if [ $# -ne 3 ]; then
    log 2 "'list_objects_with_prefix' command requires, client, bucket, prefix"
    return 1
  fi
  local result=0
  if [ "$1" == 's3' ]; then
    objects=$(send_command aws --no-verify-ssl s3 ls s3://"$2/$3" 2>&1) || result=$?
  elif [ "$1" == 's3api' ]; then
    objects=$(send_command aws --no-verify-ssl s3api list-objects --bucket "$2" --prefix "$3" 2>&1) || result=$?
  elif [ "$1" == 's3cmd' ]; then
    objects=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2/$3" 2>&1) || result=$?
  elif [[ "$1" == 'mc' ]]; then
    objects=$(send_command mc --insecure ls "$MC_ALIAS/$2/$3" 2>&1) || result=$?
  else
    log 2 "invalid command type '$1'"
    return 1
  fi
  if [ $result -ne 0 ]; then
    log 2 "error listing objects: $objects"
    return 1
  fi
  log 5 "output: $objects"
  export objects
  return 0
}

list_objects_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'list_objects_rest' requires bucket name"
    return 1
  fi

  generate_hash_for_payload ""

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  aws_endpoint_url_address=${AWS_ENDPOINT_URL#*//}
  header=$(echo "$AWS_ENDPOINT_URL" | awk -F: '{print $1}')
  # shellcheck disable=SC2154
  canonical_request="GET
/$1

host:$aws_endpoint_url_address
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
$payload_hash"

  log 5 "canonical request: $canonical_request"

  if ! generate_sts_string "$current_date_time" "$canonical_request"; then
    log 2 "error generating sts string"
    return 1
  fi
  get_signature
  # shellcheck disable=SC2154
  reply=$(send_command curl -ks "$header://$aws_endpoint_url_address/$1" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
    -H "x-amz-content-sha256: $payload_hash" \
    -H "x-amz-date: $current_date_time" 2>&1)
  log 5 "reply: $reply"
  parse_objects_list_rest
}
