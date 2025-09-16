#!/usr/bin/env bats

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

send_put_bucket_tagging_command_check_invalid_content_md5() {
  if ! check_param_count_v2 "bucket name" 1 $#; then
    return 1
  fi
  invalid_content_md5="dummy"
  if ! send_rest_go_command_expect_error_callback "400" "InvalidDigest" "was invalid" "check_invalid_content_md5" "-bucketName" "$1" "-query" "tagging=" "-method" "PUT" "-signedParams" "Content-MD5:$invalid_content_md5" \
      "-payload" "<Tagging xmlms=\\\"http://s3.amazonaws.com/doc/2006-03-01/\\\"><TagSet><Tag><Key>key</Key><Value>value</Value></Tag></TagSet></Tagging>"; then
    log 2 "error sending command and checking callback"
    return 1
  fi
  return 0
}

check_invalid_content_md5() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  # shellcheck disable=SC2154
  if ! returned_content_md5=$(get_element_text "$1" "Error" "Content-MD5"); then
    log 2 "error getting argument name"
    return 1
  fi
  if [ "$returned_content_md5" != "$invalid_content_md5" ]; then
    log 2 "expected '$invalid_content_md5', was '$returned_content_md5'"
    return 1
  fi
  return 0
}