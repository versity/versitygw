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

put_bucket_acl_success_or_access_denied() {
  if ! check_param_count_v2 "bucket, acl file, username, password, expect success" 5 $#; then
    return 1
  fi
  if [ "$5" == "true" ]; then
    if ! put_bucket_acl_rest_with_user "$3" "$4" "$1" "$2"; then
      log 2 "expected PutBucketAcl to succeed, didn't"
      return 1
    fi
  else
    if ! put_bucket_acl_rest_expect_error "$1" "$2" "AWS_ACCESS_KEY_ID=$3 AWS_SECRET_ACCESS_KEY=$4" "403" "AccessDenied" "Access Denied"; then
      log 2 "expected PutBucketAcl access denied"
      return 1
    fi
  fi
  return 0
}
