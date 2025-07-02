#!/usr/bin/env bash

source ./tests/drivers/params.sh
source ./tests/drivers/get_object_lock_config/get_object_lock_config_rest.sh
source ./tests/drivers/list_objects/list_objects_rest.sh
source ./tests/util/util_acl.sh
source ./tests/util/util_multipart_abort.sh
source ./tests/util/util_policy.sh
source ./tests/util/util_retention.sh

# restore bucket to pre-test state (or prep for deletion)
# param: bucket name
# return 0 on success, 1 on error
reset_bucket() {
  if ! check_param_count "reset_bucket" "bucket" 1 $#; then
    return 1
  fi

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

  if [ "$RUN_USERS" == "true" ] && ! change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$AWS_ACCESS_KEY_ID"; then
    log 2 "error changing bucket owner back to root"
    return 1
  fi
}

# params:  bucket name
# return 0 if able to delete recursively, 1 if not
delete_bucket_recursive() {
  log 6 "delete_bucket_recursive_s3api"
  if ! check_param_count "delete_bucket_recursive_s3api" "bucket" 1 $#; then
    return 1
  fi

  if ! reset_bucket "$1"; then
    log 2 "error clearing bucket (s3api)"
    return 1
  fi

  if ! delete_bucket_rest "$1"; then
    log 2 "error deleting bucket"
    return 1
  fi
  return 0
}

# check if bucket exists
# param:  bucket name
# return 0 for true, 1 for false, 2 for error
bucket_exists() {
  if ! check_param_count "bucket_exists" "bucket name" 1 $#; then
    return 2
  fi
  local exists=0
  head_bucket "rest" "$1" || exists=$?
  log 5 "bucket exists response code: $exists"
  # shellcheck disable=SC2181
  if [ $exists -eq 2 ]; then
    log 2 "unexpected error checking if bucket exists"
    return 2
  fi
  if [ $exists -eq 0 ]; then
    return 0
  fi
  return 1
}

direct_wait_for_bucket() {
  if ! check_param_count "direct_wait_for_bucket" "bucket" 1 $#; then
    return 1
  fi
  bucket_verification_start_time=$(date +%s)
  while ! bucket_exists "$1"; do
    bucket_verification_end_time=$(date +%s)
    if [ $((bucket_verification_end_time-bucket_verification_start_time)) -ge 60 ]; then
      log 2 "bucket existence check timeout"
      return 1
    fi
    sleep 5
  done
  return 0
}

# params:  client, bucket name
# return 0 for success, 1 for error
bucket_cleanup() {
  log 6 "bucket_cleanup"
  if ! check_param_count "bucket_cleanup" "bucket name" 1 $#; then
    return 1
  fi
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    if ! reset_bucket "$1"; then
      log 2 "error deleting bucket contents"
      return 1
    fi

    log 5 "bucket contents, policy, ACL deletion success"
    return 0
  fi
  if ! delete_bucket_recursive "$1"; then
    log 2 "error with recursive bucket delete"
    return 1
  fi
  log 5 "bucket deletion success"
  return 0
}

# params: client, bucket name
# return 0 for success, 1 for error
bucket_cleanup_if_bucket_exists() {
  log 6 "bucket_cleanup_if_bucket_exists"
  if ! check_param_count_gt "bucket name, bucket known to exist (optional)" 1 $#; then
    return 1
  fi

  if [ "$2" == "false" ]; then
    log 5 "skipping cleanup, since bucket doesn't exist"
    return 0
  fi

  if [ "$2" == "true" ] || bucket_exists "$1"; then
    if ! bucket_cleanup "$1"; then
      log 2 "error deleting bucket and/or contents"
      return 1
    fi
    log 5 "bucket and/or bucket data deletion success"
    return 0
  fi
  return 0
}

# params:  client, bucket name(s)
# return 0 for success, 1 for failure
setup_buckets() {
  if ! check_param_count_gt "minimum of 1 bucket name" 1 $#; then
    return 1
  fi
  for name in "$@"; do
    if ! setup_bucket "$name"; then
      log 2 "error setting up bucket $name"
      return 1
    fi
  done
  return 0
}

# params:  client, bucket name
# return 0 on successful setup, 1 on error
setup_bucket() {
  log 6 "setup_bucket"
  if ! check_param_count "setup_bucket" "bucket name" 1 $#; then
    return 1
  fi

  bucket_exists="true"
  if ! bucket_exists "$1"; then
    if [[ $RECREATE_BUCKETS == "false" ]]; then
      log 2 "When RECREATE_BUCKETS isn't set to \"true\", buckets should be pre-created by user"
      return 1
    fi
    bucket_exists="false"
  fi

  if ! bucket_cleanup_if_bucket_exists "$1" "$bucket_exists"; then
    log 2 "error deleting bucket or contents if they exist"
    return 1
  fi

  log 5 "util.setup_bucket: bucket name: $1"
  if [[ $RECREATE_BUCKETS == "true" ]]; then
    if ! create_bucket "s3api" "$1"; then
      log 2 "error creating bucket"
      return 1
    fi
  else
    log 5 "skipping bucket re-creation"
  fi

  # bucket creation and resets take longer to propagate in direct mode
  if [ "$DIRECT" == "true" ] && ! direct_wait_for_bucket "$1"; then
    return 1
  fi

  if [[ $1 == "s3cmd" ]]; then
    log 5 "putting bucket ownership controls"
    if bucket_exists "$1" && ! put_bucket_ownership_controls "$1" "BucketOwnerPreferred"; then
      log 2 "error putting bucket ownership controls"
      return 1
    fi
  fi
  return 0
}

# check if bucket info can be retrieved
# param:  path of bucket or folder
# return 0 for yes, 1 for no, 2 for error
bucket_is_accessible() {
  if ! check_param_count "bucket_is_accessible" "bucket" 1 $#; then
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws --no-verify-ssl s3api head-bucket --bucket "$1" 2>&1) || exit_code="$?"
  if [ $exit_code -eq 0 ]; then
    return 0
  fi
  if [[ "$error" == *"500"* ]]; then
    return 1
  fi
  log 2 "Error checking bucket accessibility: $error"
  return 2
}

check_for_empty_region() {
  if ! check_param_count "check_for_empty_region" "bucket" 1 $#; then
    return 2
  fi
  if ! head_bucket "s3api" "$BUCKET_ONE_NAME"; then
    log 2 "error getting bucket info"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "INFO:  $bucket_info"
  if ! region=$(echo "$bucket_info" | grep -v "InsecureRequestWarning" | jq -r ".BucketRegion" 2>&1); then
    log 2 "error getting region: $region"
    return 1
  fi
  if [[ $region == "" ]]; then
    log 2 "empty bucket region"
    return 1
  fi
  return 0
}
