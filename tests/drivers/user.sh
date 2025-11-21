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

source ./tests/drivers/delete_object/delete_object_rest.sh
source ./tests/drivers/get_object_lock_config/get_object_lock_config_rest.sh
source ./tests/drivers/put_bucket_acl/put_bucket_acl_rest.sh
source ./tests/drivers/file.sh
source ./tests/util/util_multipart_abort.sh
source ./tests/util/util_policy.sh
source ./tests/util/util_retention.sh
source ./tests/util/util_users.sh

create_versitygw_acl_user_or_get_direct_user() {
  if [ $# -ne 2 ]; then
    log 2 "'create_versitygw_acl_user_or_get_direct_user' requires username, password"
    return 1
  fi
  if [ "$DIRECT" == "true" ]; then
    if [ -z "$AWS_CANONICAL_ID" ] || [ -z "$ACL_AWS_CANONICAL_ID" ] || [ -z "$ACL_AWS_ACCESS_KEY_ID" ] || [ -z "$ACL_AWS_SECRET_ACCESS_KEY" ]; then
      log 2 "direct ACL calls require the following env vars: AWS_CANONICAL_ID, ACL_AWS_CANONICAL_ID, ACL_AWS_ACCESS_KEY_ID, ACL_AWS_SECRET_ACCESS_KEY"
      return 1
    fi
    owner_canonical_id="$AWS_CANONICAL_ID"
    user_canonical_id="$ACL_AWS_CANONICAL_ID"
    username="$ACL_AWS_ACCESS_KEY_ID"
    password="$ACL_AWS_SECRET_ACCESS_KEY"
  else
    owner_canonical_id="$AWS_ACCESS_KEY_ID"
    if ! create_user_versitygw "$1" "$2" "user"; then
      log 2 "error creating versitygw user"
      return 1
    fi
    # shellcheck disable=SC2154
    user_canonical_id="$1"
    username="$1"
    # shellcheck disable=SC2154
    password="$2"
  fi
  echo "$owner_canonical_id"
  echo "$user_canonical_id"
  echo "$username"
  echo "$password"
}

setup_bucket_and_user() {
  if ! check_param_count_v2 "bucket or prefix, username, password, user type" 4 $#; then
    return 1
  fi
  if ! setup_bucket_v2 "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! result=$(setup_user_versitygw_or_direct "$2" "$3" "$4" "$1"); then
    log 2 "error setting up user"
    return 1
  fi
  echo "$result"
  return 0
}

setup_bucket_and_acl_user() {
  if ! check_param_count_v2 "bucket, username, password" 3 $#; then
    return 1
  fi
  if ! setup_bucket_v2 "$1"; then
    log 2 "error setting up bucket"
    return 1
  fi
  if ! result=$(create_versitygw_acl_user_or_get_direct_user "$2" "$3"); then
    log 2 "error creating or getting user"
    return 1
  fi
  echo "$result"
  return 0
}

setup_bucket_file_and_user() {
  if ! check_param_count "setup_bucket_file_and_user" "bucket, file, username, password, user type" 5 $#; then
    return 1
  fi
  if ! setup_bucket_and_files "$1" "$2"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  if ! result=$(setup_user_versitygw_or_direct "$3" "$4" "$5" "$1"); then
    log 2 "error setting up user"
    return 1
  fi
  echo "$result"
  return 0
}

setup_bucket_file_and_user_v2() {
  if ! check_param_count_v2 "bucket name or prefix, file, username, password, user type" 5 $#; then
    return 1
  fi
  if ! setup_bucket_and_files_v2 "$1" "$2"; then
    log 2 "error setting up bucket and file"
    return 1
  fi
  if ! result=$(setup_user_versitygw_or_direct "$3" "$4" "$5" "$1"); then
    log 2 "error setting up user"
    return 1
  fi
  echo "$result"
  return 0
}

reset_bucket() {
  if ! check_param_count "reset_bucket" "bucket" 1 $#; then
    return 1
  fi
  log 6 "reset bucket '$1'"

  if [[ $LOG_LEVEL_INT -ge 5 ]] && ! log_bucket_policy "$1"; then
    log 3 "error logging bucket policy"
  fi

  if ! check_object_lock_config "$1"; then
    log 2 "error checking object lock config"
    return 1
  fi

  if [[ "$DIRECT" != "true" ]] && ! add_governance_bypass_policy "$1"; then
    log 2 "error adding governance bypass policy"
    return 1
  fi

  if ! list_and_delete_objects "$1"; then
    log 2 "error listing and deleting objects"
    return 1
  fi

  if ! abort_all_multipart_uploads_rest "$1"; then
    log 2 "error aborting all multipart uploads"
    return 1
  fi

  if [ "$SKIP_ACL_TESTING" != "true" ] && ! check_ownership_rule_and_reset_acl "$1"; then
    log 2 "error checking ownership rule and resetting acl"
    return 1
  fi

  if ! delete_bucket_policy_rest "$1"; then
    log 2 "error deleting bucket policy"
    return 1
  fi

  # shellcheck disable=SC2154
  if [[ $lock_config_exists == true ]] && ! remove_retention_policy_rest "$1"; then
    log 2 "error removing bucket retention policy"
    return 1
  fi

  if [ "$RUN_USERS" == "true" ] && [ "$DIRECT" != "true" ] && ! change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$AWS_ACCESS_KEY_ID"; then
    log 2 "error changing bucket owner back to root"
    return 1
  fi
}
