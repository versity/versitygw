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

source ./tests/logger.sh
source ./tests/setup.sh
source ./tests/test_s3api_policy_bucket.sh
source ./tests/test_s3api_policy_multipart.sh
source ./tests/test_s3api_policy_object.sh
source ./tests/util/util_multipart.sh
source ./tests/util/util_multipart_abort.sh
source ./tests/util/util_multipart_before_completion.sh
source ./tests/util/util_file.sh
source ./tests/util/util_policy.sh
source ./tests/util/util_users.sh
source ./tests/commands/get_bucket_policy.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/get_object.sh
source ./tests/commands/put_bucket_policy.sh
source ./tests/commands/put_bucket_tagging.sh
source ./tests/commands/put_object.sh
source ./tests/drivers/get_bucket_acl/get_bucket_acl_s3api.sh
source ./tests/drivers/get_bucket_tagging/get_bucket_tagging_rest.sh

export RUN_USERS=true

if [ -n "$SKIP_POLICY" ] || [ "$SKIP_USERS_TESTS" == "true" ]; then
  skip "Skipping ACL tests"
  exit 0
fi

@test "test_policy_abort_multipart_upload" {
  test_s3api_policy_abort_multipart_upload
}

@test "test_policy_allow_deny" {
  test_s3api_policy_allow_deny
}

@test "test_policy_delete" {
  test_s3api_policy_delete
}

@test "test_policy_delete_bucket_policy" {
  test_s3api_policy_delete_bucket_policy
}

@test "test_policy_deny" {
  test_s3api_policy_deny
}

@test "test_policy_get_bucket_acl" {
  test_s3api_policy_get_bucket_acl
}

@test "test_policy_get_bucket_policy" {
  test_s3api_policy_get_bucket_policy
}

@test "test_policy_get_bucket_tagging" {
  test_s3api_policy_get_bucket_tagging
}

@test "test_policy_get_object_file_wildcard" {
  test_s3api_policy_get_object_file_wildcard
}

@test "test_policy_get_object_folder_wildcard" {
  test_s3api_policy_get_object_folder_wildcard
}

@test "test_policy_get_object_specific_file" {
  test_s3api_policy_get_object_specific_file
}

@test "test_policy_get_object_with_user" {
  test_s3api_policy_get_object_with_user
}

@test "test_policy_list_multipart_uploads" {
  test_s3api_policy_list_multipart_uploads
}

@test "test_policy_list_upload_parts" {
  test_s3api_policy_list_upload_parts
}

@test "test_policy_put_acl" {
  test_s3api_policy_put_acl
}

@test "test_policy_put_bucket_policy" {
  test_s3api_policy_put_bucket_policy
}

@test "test_policy_put_bucket_tagging" {
  test_s3api_policy_put_bucket_tagging
}

@test "test_policy_two_principals" {
  test_s3api_policy_two_principals
}

@test "test_policy_put_wildcard" {
  test_s3api_policy_put_wildcard
}

@test "test_put_policy_invalid_action" {
  test_s3api_policy_invalid_action
}
