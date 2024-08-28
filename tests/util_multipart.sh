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

create_upload_and_test_parts_listing() {
  if [ $# -ne 2 ]; then
    log 2 "'create_upload_and_test_parts_listing' requires test file, policy_file"
    return 1
  fi
  if ! create_multipart_upload_with_user "$BUCKET_ONE_NAME" "$1" "$USERNAME_ONE" "$PASSWORD_ONE"; then
    log 2 "error creating multipart upload with user"
    return 1
  fi

  # shellcheck disable=SC2154
  if list_parts_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$1" "$upload_id"; then
    log 2 "list parts with user succeeded despite lack of policy permissions"
    return 1
  fi

  if ! setup_policy_with_single_statement "$TEST_FILE_FOLDER/$2" "2012-10-17" "Allow" "$USERNAME_ONE" "s3:ListMultipartUploadParts" "arn:aws:s3:::$BUCKET_ONE_NAME/*"; then
    log 2 "error setting up policy"
    return 1
  fi

  if ! put_bucket_policy "s3api" "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$2"; then
    log 2 "error putting policy"
    return 1
  fi

  if ! list_parts_with_user "$USERNAME_ONE" "$PASSWORD_ONE" "$BUCKET_ONE_NAME" "$1" "$upload_id"; then
    log 2 "error listing parts after policy add"
    return 1
  fi
  return 0
}
