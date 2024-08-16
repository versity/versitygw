#!/usr/bin/env bash

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
