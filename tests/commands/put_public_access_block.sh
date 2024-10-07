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

put_public_access_block() {
  if [[ $# -ne 2 ]]; then
    log 2 "'put_public_access_block' command requires bucket, access block list"
    return 1
  fi
  if ! error=$(send_command aws --no-verify-ssl s3api put-public-access-block --bucket "$1" --public-access-block-configuration "$2"); then
    log 2 "error updating public access block: $error"
    return 1
  fi
}

put_public_access_block_enable_public_acls() {
  if [[ $# -ne 1 ]]; then
    log 2 "command requires bucket"
    return 1
  fi
  if ! put_public_access_block "$1" "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=true,RestrictPublicBuckets=true"; then
    log 2 "error putting public acccess block"
    return 1
  fi
  return 0
}

put_public_access_block_disable_public_acls() {
  if [[ $# -ne 1 ]]; then
    log 2 "command requires bucket"
    return 1
  fi
  if ! put_public_access_block "$1" "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"; then
    log 2 "error putting public access block"
    return 1
  fi
  return 0
}

