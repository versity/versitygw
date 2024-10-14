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

source ./tests/util_file.sh
source ./tests/commands/command.sh

put_bucket_acl_s3api() {
  log 6 "put_bucket_acl_s3api"
  record_command "put-bucket-acl" "client:s3api"
  if [[ $# -ne 2 ]]; then
    log 2 "put bucket acl command requires bucket name, acl file"
    return 1
  fi
  log 5 "bucket name: $1, acls: $2"
  if ! error=$(send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --access-control-policy "file://$2" 2>&1); then
    log 2 "error putting bucket acl: $error"
    return 1
  fi
  return 0
}

put_bucket_acl_s3api_with_user() {
  log 6 "put_bucket_acl_s3api_with_user"
  record_command "put-bucket-acl" "client:s3api"
  if [[ $# -ne 4 ]]; then
    log 2 "put bucket acl command requires bucket name, acl file, username, password"
    return 1
  fi
  log 5 "bucket name: $1, acls: $2"
  if ! error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --access-control-policy "file://$2" 2>&1); then
    log 2 "error putting bucket acl: $error"
    return 1
  fi
  return 0
}

reset_bucket_acl() {
  if [ $# -ne 1 ]; then
    log 2 "'reset_bucket_acl' requires bucket name"
    return 1
  fi
  acl_file="acl_file"
  if ! create_test_files "$acl_file"; then
    log 2 "error creating test files"
    return 1
  fi
  # shellcheck disable=SC2154
  cat <<EOF > "$TEST_FILE_FOLDER/$acl_file"
{
  "Grants": [
    {
      "Grantee": {
        "ID": "$AWS_ACCESS_KEY_ID",
        "Type": "CanonicalUser"
      },
      "Permission": "FULL_CONTROL"
    }
  ],
  "Owner": {
    "ID": "$AWS_ACCESS_KEY_ID"
  }
}
EOF
  if ! put_bucket_acl_s3api "$BUCKET_ONE_NAME" "$TEST_FILE_FOLDER/$acl_file"; then
    log 2 "error putting bucket acl (s3api)"
    return 1
  fi
  delete_test_files "$acl_file"
  return 0
}

put_bucket_canned_acl_s3cmd() {
  record_command "put-bucket-acl" "client:s3cmd"
  if [[ $# -ne 2 ]]; then
    log 2 "put bucket acl command requires bucket name, permission"
    return 1
  fi
  if ! error=$(send_command s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setacl "s3://$1" "$2" 2>&1); then
    log 2 "error putting s3cmd canned ACL:  $error"
    return 1
  fi
  return 0
}

put_bucket_canned_acl() {
  if [[ $# -ne 2 ]]; then
    log 2 "'put bucket canned acl' command requires bucket name, canned ACL"
    return 1
  fi
  record_command "put-bucket-acl" "client:s3api"
  if ! error=$(send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --acl "$2" 2>&1); then
    log 2 "error re-setting bucket acls: $error"
    return 1
  fi
  return 0
}

put_bucket_canned_acl_with_user() {
  if [[ $# -ne 4 ]]; then
    log 2 "'put bucket canned acl with user' command requires bucket name, canned ACL, username, password"
    return 1
  fi
  record_command "put-bucket-acl" "client:s3api"
  if ! error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" send_command aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --acl "$2" 2>&1); then
    log 2 "error re-setting bucket acls: $error"
    return 1
  fi
  return 0
}
