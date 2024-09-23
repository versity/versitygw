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

list_object_versions() {
  record_command "list-object-versions" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "'list object versions' command requires bucket name"
    return 1
  fi
  versions=$(aws --no-verify-ssl s3api list-object-versions --bucket "$1" 2>&1) || local list_result=$?
  if [[ $list_result -ne 0 ]]; then
    log 2 "error listing object versions: $versions"
    return 1
  fi
  versions=$(echo "$versions" | grep -v "InsecureRequestWarning")
  return 0
}

list_object_versions_rest() {
  if [ $# -ne 1 ]; then
    log 2 "'list_object_versions_rest' requires bucket name"
    return 1
  fi
  generate_hash_for_payload ""

  current_date_time=$(date -u +"%Y%m%dT%H%M%SZ")
  # shellcheck disable=SC2154
  canonical_request="GET
/$1
versions=
host:${AWS_ENDPOINT_URL#*//}
x-amz-content-sha256:$payload_hash
x-amz-date:$current_date_time

host;x-amz-content-sha256;x-amz-date
$payload_hash"

  if ! generate_sts_string "$current_date_time" "$canonical_request"; then
    log 2 "error generating sts string"
    return 1
  fi

  get_signature
  # shellcheck disable=SC2034,SC2154
  reply=$(curl -ks "$AWS_ENDPOINT_URL/$1?versions" \
         -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$ymd/$AWS_REGION/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=$signature" \
         -H "x-amz-content-sha256: $payload_hash" \
         -H "x-amz-date: $current_date_time" \
         -o "$TEST_FILE_FOLDER/object_versions.txt" 2>&1)
}