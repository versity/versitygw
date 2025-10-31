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

load ./bats-support/load
load ./bats-assert/load

source ./tests/setup.sh
source ./tests/drivers/rest.sh
source ./tests/drivers/user.sh
source ./tests/drivers/create_bucket/create_bucket_rest.sh
source ./tests/drivers/delete_bucket_tagging/delete_bucket_tagging_rest.sh
source ./tests/drivers/get_bucket_tagging/get_bucket_tagging_rest.sh

export RUN_USERS=true

@test "REST - DeleteBucketTagging - lack permission" {
  if [ "$SKIP_USERS_TESTS" == "true" ]; then
    skip
  fi
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_and_acl_user "$bucket_name" "$USERNAME_ONE" "$PASSWORD_ONE"
  assert_success
  username=${lines[${#lines[@]}-2]}
  password=${lines[${#lines[@]}-1]}

  run send_rest_go_command_expect_error "403" "AccessDenied" "Access Denied" "-awsAccessKeyId" "$username" "-awsSecretAccessKey" "$password" \
    "-method" "DELETE" "-bucketName" "$bucket_name" "-query" "tagging="
  assert_success
}

@test "REST - DeleteBucketTagging - success" {
  run get_bucket_name "$BUCKET_ONE_NAME"
  assert_success
  bucket_name="$output"

  run setup_bucket_v2 "$bucket_name"
  assert_success

  run add_verify_bucket_tags_rest "$bucket_name" "key" "value"
  assert_success

  run delete_tags_and_verify_deletion "$bucket_name"
  assert_success
}
