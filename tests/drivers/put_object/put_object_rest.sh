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

put_object_success_or_access_denied() {
  if ! check_param_count_v2 "username, password, data file, bucket, key, expect success" 6 $#; then
    return 1
  fi
  if [ "$6" == "true" ]; then
    if ! put_object_rest_with_user "$1" "$2" "$3" "$4" "$5"; then
      log 2 "expected PutObject to succeed, didn't"
      return 1
    fi
  else
    if ! put_object_rest_expect_error "$3" "$4" "$5" "AWS_ACCESS_KEY_ID=$1 AWS_SECRET_ACCESS_KEY=$2" "403" "AccessDenied" "Access Denied"; then
      log 2 "expected GetBucketAcl access denied"
      return 1
    fi
    if ! put_object_rest "$3" "$4" "$5"; then
      log 2 "error putting object with root account"
      return 1
    fi
  fi
  return 0
}

setup_bucket_and_add_file() {
  if ! check_param_count_v2 "bucket, filename" 2 $#; then
    return 1
  fi
  if ! setup_bucket_v2 "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! create_test_files "$2"; then
    log 2 "error creating test file"
    return 1
  fi
  if ! put_object_rest "$TEST_FILE_FOLDER/$2" "$1" "$2"; then
    log 2 "error putting REST object"
    return 1
  fi
  return 0
}

send_openssl_go_command_chunked_no_content_length() {
  if ! check_param_count_gt "bucket name, key" 2 $#; then
    return 1
  fi
  run send_openssl_go_command_expect_error "400" "IncompleteBody" "The request body terminated unexpectedly" \
      "-client" "openssl" "-commandType" "putObject" "-bucketName" "$1" "-payload" "abcdefg" "-omitContentLength" \
      "-payloadType" "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" "-chunkSize" "8192" "-objectKey" "$2"
    assert_success
}
