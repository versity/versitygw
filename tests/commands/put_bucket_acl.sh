#!/usr/bin/env bash

source ./tests/util_file.sh

put_bucket_acl_s3api() {
  record_command "put-bucket-acl" "client:$1"
  if [[ $# -ne 3 ]]; then
    log 2 "put bucket acl command requires command type, bucket name, acls or username"
    return 1
  fi
  log 5 "bucket name: $2, acls: $3"
  if ! error=$(aws --no-verify-ssl s3api put-bucket-acl --bucket "$2" --access-control-policy "file://$3" 2>&1); then
    log 2 "error putting bucket acl: $error"
    return 1
  fi
  return 0
}

reset_bucket_acl() {
  #if [[ $# -ne 1 ]]; then
  #  log 2 "'reset_bucket_acl' requires bucket name"
  #  return 1
  #fi
  assert [ $# -eq 1 ]
  acl_file="acl_file"
  run create_test_files "$acl_file"
  assert_success "error creating file"
  # shellcheck disable=SC2154
  cat <<EOF > "$test_file_folder/$acl_file"
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
  run put_bucket_acl_s3api "s3api" "$BUCKET_ONE_NAME" "$test_file_folder/$acl_file"
  assert_success "error putting bucket ACL"
  delete_test_files "$acl_file"
}

put_bucket_canned_acl_s3cmd() {
  record_command "put-bucket-acl" "client:s3cmd"
  if [[ $# -ne 2 ]]; then
    log 2 "put bucket acl command requires bucket name, permission"
    return 1
  fi
  if ! error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate setacl "s3://$1" "$2" 2>&1); then
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
  if ! error=$(aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --acl "$2" 2>&1); then
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
  if ! error=$(AWS_ACCESS_KEY_ID="$3" AWS_SECRET_ACCESS_KEY="$4" aws --no-verify-ssl s3api put-bucket-acl --bucket "$1" --acl "$2" 2>&1); then
    log 2 "error re-setting bucket acls: $error"
    return 1
  fi
  return 0
}
