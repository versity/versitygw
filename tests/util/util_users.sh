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

setup_user() {
  log 6 "setup_user"
  if [[ $# -ne 3 ]]; then
    log 2 "'setup user' command requires username, password, and role"
    return 1
  fi
  if user_exists "$1"; then
    if ! delete_user "$1"; then
      log 2 "error deleting user '$1'"
      return 1
    fi
  fi
  if ! create_user_versitygw "$1" "$2" "$3"; then
    log 2 "error creating user '$1'"
    return 1
  fi
  return 0
}

setup_user_direct() {
  log 6 "setup_user_direct"
  log 5 "username: $1, role: $2, bucket: $3"
  if [[ $# -ne 3 ]]; then
    log 2 "'setup user direct' command requires username, role, and bucket"
    return 1
  fi
  if user_exists "$1"; then
    if ! delete_user "$1"; then
      log 2 "error deleting user '$1'"
      return 1
    fi
  fi
  if ! create_user_direct "$1" "$2" "$3"; then
    log 2 "error creating direct user"
    return 1
  fi
  return 0
}

setup_user_versitygw_or_direct() {
  if [ $# -ne 4 ]; then
    # NOTE:  bucket name is required for direct
    log 2 "'setup_user_versitygw_or_direct' requires username, password, role, bucket name"
    return 1
  fi
  if [ "$DIRECT" != "true" ]; then
    if ! setup_user "$1" "$2" "$3"; then
      log 2 "error setting up versitygw user"
      return 1
    fi
    echo "$1"
    echo "$1"
    echo "$2"
  else
    if ! setup_user_direct "$1" "$3" "$4"; then
      log 2 "error setting up direct user"
      return 1
    fi
    echo "$1"
    echo "$key_id"
    echo "$secret_key"
  fi
  return 0
}

create_user_versitygw() {
  log 6 "create_user_versitygw"
  if [[ $# -ne 3 ]]; then
    log 2 "create user command requires user ID, key, and role"
    return 1
  fi
  if ! create_user_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2" "$3"; then
    log 2 "error creating versitygw user"
    return 1
  fi
  return 0
}

create_user_if_nonexistent() {
  log 6 "create_user_if_nonexistent"
  if [[ $# -ne 3 ]]; then
    log 2 "create user command requires user ID, key, and role"
    return 1
  fi
  if user_exists "$1"; then
    log 5 "user $1 already exists"
    return 0
  fi
  setup_user_versitygw_or_direct "$1" "$2" "$3" "$BUCKET_ONE_NAME"
  return $?
}

put_user_policy_userplus() {
  log 6 "put_user_policy_userplus"
  if [[ $# -ne 1 ]]; then
    log 2 "'put user policy userplus' function requires username"
    return 1
  fi

  cat <<EOF > "$TEST_FILE_FOLDER"/user_policy_file
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Effect": "Allow",
          "Action": [
              "s3:CreateBucket",
              "s3:ListBucket",
              "s3:ListAllMyBuckets",
              "s3:ListBucketMultipartUploads",
              "s3:GetBucketLocation"
          ],
          "Resource": "arn:aws:s3:::$1-*"
      },
      {
          "Effect": "Allow",
          "Action": "s3:*",
          "Resource": [
              "arn:aws:s3:::$1-*",
              "arn:aws:s3:::$1-*/*"
          ]
      }
  ]
}
EOF
  if ! error=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam put-user-policy --user-name "$1" --policy-name "UserPolicy" --policy-document "file://$TEST_FILE_FOLDER/user_policy_file" 2>&1); then
    log 2 "error putting user policy: $error"
    return 1
  fi
  return 0
}

put_user_policy_admin() {
  log 6 "put_user_policy_admin"
  if [[ $# -ne 2 ]]; then
    log 2 "'put user policy admin' function requires username, bucket name"
    return 1
  fi

  cat <<EOF > "$TEST_FILE_FOLDER"/user_policy_file
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Effect": "Allow",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::$1-*",
            "arn:aws:s3:::$1-*/*",
            "arn:aws:s3:::$2",
            "arn:aws:s3:::$2/*"
          ]
      }
  ]
}
EOF
  if ! error=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam put-user-policy --user-name "$1" --policy-name "UserPolicy" --policy-document "file://$TEST_FILE_FOLDER/user_policy_file" 2>&1); then
    log 2 "error putting user policy: $error"
    return 1
  fi
  return 0
}

put_user_policy() {
  log 6 "put_user_policy"
  if [[ $# -ne 3 ]]; then
    log 2 "attaching user policy requires user ID, role, bucket name"
    return 1
  fi

  case $2 in
  "user")
    ;;
  "userplus")
    if ! put_user_policy_userplus "$1"; then
      log 2 "error adding userplus policy"
      return 1
    fi
    ;;
  "admin")
    if ! put_user_policy_admin "$1" "$3"; then
      log 2 "error adding userplus policy"
      return 1
    fi
    ;;
  *)
    log 2 "unrecognized user type '$2' for putting policy"
    return 1
    ;;
  esac
  return 0
}

create_user_direct() {
  log 6 "create_user_direct"
  if [[ $# -ne 3 ]]; then
    log 2 "create user direct command requires desired username, role, bucket name"
    return 1
  fi
  if ! error=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam create-user --user-name "$1" 2>&1); then
    log 2 "error creating new user: $error"
    return 1
  fi
  if ! put_user_policy "$1" "$2" "$3"; then
    log 2 "error attaching user policy"
    return 1
  fi
  if ! keys=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam create-access-key --user-name "$1" 2>&1); then
    log 2 "error creating keys for new user: $keys"
    return 1
  fi
  key_id=$(echo "$keys" | jq -r ".AccessKey.AccessKeyId")
  export key_id
  secret_key=$(echo "$keys" | jq -r ".AccessKey.SecretAccessKey")
  export secret_key

  # propagation delay occurs when user is added to IAM, so wait a few seconds
  sleep 10

  return 0
}

create_user_with_user() {
  log 6 "create_user_with_user"
  if [[ $# -ne 5 ]]; then
    log 2 "create user with user command requires creator ID, key, and new user ID, key, and role"
    return 1
  fi
  if ! error=$(send_command "$VERSITY_EXE" admin --allow-insecure --access "$1" --secret "$2" --endpoint-url "$AWS_ENDPOINT_URL" create-user --access "$3" --secret "$4" --role "$5" 2>&1); then
    log 2 "error creating user: $error"
    return 1
  fi
  return 0
}

list_users_direct() {
  log 6 "list_users_direct"
  # AWS_ENDPOINT_URL of s3.amazonaws.com doesn't work here
  if ! users=$(send_command aws --profile="$AWS_PROFILE" --endpoint-url=https://iam.amazonaws.com iam list-users 2>&1); then
    log 2 "error listing users via direct s3 call: $users"
    return 1
  fi
  parsed_users=()
  if ! users_list=$(echo "$users" | jq -r ".Users[].UserName" 2>&1); then
    log 2 "error parsing users array: $users_list"
    return 1
  fi
  while IFS= read -r line; do
    parsed_users+=("$line")
  done <<< "$users_list"
  log 5 "parsed users: ${parsed_users[*]}"
  export parsed_users
  return 0
}

list_users() {
  log 6 "list_users"
  if [[ $DIRECT == "true" ]]; then
    if ! list_users_direct; then
      log 2 "error listing users via direct s3 call"
      return 1
    fi
    return 0
  fi
  if ! list_users_versitygw; then
    log 2 "error listing versitygw users"
    return 1
  fi
  return 0
}

list_users_versitygw() {
  log 6 "list_users_versitygw"
  users=$(send_command "$VERSITY_EXE" admin --allow-insecure --access "$AWS_ACCESS_KEY_ID" --secret "$AWS_SECRET_ACCESS_KEY" --endpoint-url "$AWS_ENDPOINT_URL" list-users 2>&1) || local list_result=$?
  if [[ $list_result -ne 0 ]]; then
    log 2 "error listing users: $users"
    return 1
  fi
  parsed_users=()
  while IFS= read -r line; do
    parsed_users+=("$line")
  done < <(awk 'NR>2 {print $1}' <<< "$users")
  export parsed_users
  return 0
}

user_exists() {
  log 6 "user_exists"
  if [[ $# -ne 1 ]]; then
    log 2 "user exists command requires username"
    return 2
  fi
  if ! list_users; then
    log 2 "error listing user"
    return 2
  fi
  for element in "${parsed_users[@]}"; do
    log 5 "user: $element"
    if [[ $element == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

delete_user_direct() {
  log 6 "delete_user_direct"
  if [[ $# -ne 1 ]]; then
    log 2 "delete user direct command requires username"
    return 1
  fi
  if ! policies=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam list-user-policies --user-name "$1" --query 'PolicyNames' --output text 2>&1); then
    log 2 "error getting user policies: $error"
    return 1
  fi
  for policy_name in $policies; do
    if ! user_policy_delete_error=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam delete-user-policy --user-name "$1" --policy-name "$policy_name" 2>&1); then
      log 2 "error deleting user policy: $user_policy_delete_error"
      return 1
    fi
  done
  if ! keys=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam list-access-keys --user-name "$1" 2>&1); then
    log 2 "error getting keys: $keys"
    return 1
  fi
  if ! key=$(echo "$keys" | jq -r ".AccessKeyMetadata[0].AccessKeyId" 2>&1); then
    log 2 "error getting key ID: $key"
    return 1
  fi
  if [[ $key != "null" ]]; then
    if ! error=$(send_command aws --endpoint-url=https://iam.amazonaws.com iam delete-access-key --user-name "$1" --access-key-id "$key" 2>&1); then
      log 2 "error deleting access key: $error"
      return 1
    fi
  fi
  if ! error=$(send_command aws --endpoint-url=https://iam.amazonaws.com --profile="$AWS_PROFILE" iam delete-user --user-name "$1" 2>&1); then
    log 2 "error deleting user: $error"
    return 1
  fi
  return 0
}

delete_user_versitygw() {
  log 6 "delete_user_versitygw"
  if [[ $# -ne 1 ]]; then
    log 2 "delete user via versitygw command requires user ID or username"
    return 1
  fi
  log 5 "$VERSITY_EXE admin --allow-insecure --access $AWS_ACCESS_KEY_ID --secret $AWS_SECRET_ACCESS_KEY --endpoint-url $AWS_ENDPOINT_URL delete-user --access $1"
  if ! error=$(send_command "$VERSITY_EXE" admin --allow-insecure --access "$AWS_ACCESS_KEY_ID" --secret "$AWS_SECRET_ACCESS_KEY" --endpoint-url "$AWS_ENDPOINT_URL" delete-user --access "$1" 2>&1); then
    log 2 "error deleting user: $error"
    export error
    return 1
  fi
  return 0
}

delete_user() {
  log 6 "delete_user"
  if [[ $# -ne 1 ]]; then
    log 2 "delete user command requires user ID"
    return 1
  fi
  if [[ $DIRECT == "true" ]]; then
    if ! delete_user_direct "$1"; then
      log 2 "error deleting user direct via s3"
      return 1
    fi
    log 5 "user '$1' deleted successfully"
    return 0
  fi
  if ! delete_user_versitygw "$1"; then
    log 2 "error deleting user via versitygw"
    return 1
  fi
}

change_bucket_owner_direct() {
  log 6 "change_bucket_owner_direct"
  if [[ $# -ne 4 ]]; then
    log 2 "change bucket owner command requires ID, key, bucket name, and new owner"
    return 1
  fi
  # TODO add
}

reset_bucket_owner() {
  if [ $# -ne 1 ]; then
    log 2 "'reset_bucket_owner' requires bucket name"
    return 1
  fi
  if ! change_bucket_owner "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$AWS_ACCESS_KEY_ID"; then
    log 2 "error changing bucket owner back to root"
    return 1
  fi
  return 0
}

change_bucket_owner() {
  log 6 "change_bucket_owner"
  if [[ $# -ne 4 ]]; then
    log 2 "change bucket owner command requires ID, key, bucket name, and new owner"
    return 1
  fi
  if [[ $DIRECT == "true" ]]; then
    if ! change_bucket_owner_direct "$1" "$2" "$3" "$4"; then
      log 2 "error changing bucket owner direct to s3"
      return 1
    fi
    return 0
  fi
  log 5 "changing owner for bucket $3, new owner: $4"
  error=$(send_command "$VERSITY_EXE" admin --allow-insecure --access "$1" --secret "$2" --endpoint-url "$AWS_ENDPOINT_URL" change-bucket-owner --bucket "$3" --owner "$4" 2>&1) || local change_result=$?
  if [[ $change_result -ne 0 ]]; then
    log 2 "error changing bucket owner: $error"
    return 1
  fi
  return 0
}

get_bucket_owner() {
  log 6 "get_bucket_owner"
  if [[ $# -ne 1 ]]; then
    log 2 "'get bucket owner' command requires bucket name"
    return 1
  fi
  if ! buckets=$(send_command "$VERSITY_EXE" admin --allow-insecure --access "$AWS_ACCESS_KEY_ID" --secret "$AWS_SECRET_ACCESS_KEY" --endpoint-url "$AWS_ENDPOINT_URL" list-buckets 2>&1); then
    log 2 "error listing buckets: $buckets"
    return 1
  fi
  log 5 "BUCKET DATA:  $buckets"
  bucket_vals=$(echo "$buckets" | awk 'NR > 2')
  while IFS= read -r line; do
    log 5 "bucket line: $line"
    bucket=$(echo "$line" | awk '{print $1}')
    if [[ $bucket == "$1" ]]; then
      bucket_owner=$(echo "$line" | awk '{print $2}')
      export bucket_owner
      return 0
    fi
  done <<< "$bucket_vals"
  log 3 "bucket owner for bucket '$1' not found"
  bucket_owner=
  return 0
}

verify_user_cant_get_object() {
  if [ $# -ne 6 ]; then
    log 2 "'verify_user_cant_get_object' requires client, bucket, key, save file, username, password"
    return 1
  fi
  if get_object_with_user "$1" "$2" "$3" "$4" "$5" "$6"; then
    log 2 "get object with user succeeded despite lack of permissions"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$get_object_error" != *"AccessDenied"* ]]; then
    log 2 "invalid get object error: $get_object_error"
    return 1
  fi
  return 0
}

get_username_and_password() {
  if [ $# -ne 3 ]; then
    log 2 "'get_username_and_password' requires role, number, bucket name"
    return 1
  fi
  if [ "$AUTOGENERATE_USERS" == "true" ]; then
    # NOTE:  for direct users, username and password will be replaced by key ID, secret key
    user_id="${USER_AUTOGENERATION_PREFIX}$2"
    username="$user_id"
    password="abc123-${1}-${2}"
  else
    uppercase_role=$(echo "$1" | tr '[:lower:]' '[:upper:]')
    user_id_var="USER_ID_${uppercase_role}_${2}"
    user_id=${!user_id_var}
    if [ "$user_id" == "" ]; then
      log 2 "test requires env param $user_id_var"
      return 1
    fi
    username_var="USERNAME_${uppercase_role}_${2}"
    username=${!username_var}
    if [ "$username" == "" ]; then
      log 2 "test requires env param $username_var"
      return 1
    fi
    password_var="PASSWORD_${uppercase_role}_${2}"
    password=${!password_var}
    if [ "$password" == "" ]; then
      log 2 "test requires env param $password_var"
      return 1
    fi
  fi
  return 0
}

delete_autogenerated_users() {
  if [ "$USER_AUTOGENERATION_PREFIX" == "" ]; then
    log 5 "USER_AUTOGENERATION_PREFIX must be defined to delete autogenerated users"
    return 0
  fi
  if ! list_users; then
    log 2 "error listing users"
    return 1
  fi
  for user in "${parsed_users[@]}"; do
    if [[ "$user" == "$USER_AUTOGENERATION_PREFIX"* ]]; then
      log 5 "matched user: $user"
      if ! delete_user "$user"; then
        log 2 "error deleting autogenerated user"
        return 1
      fi
      log 5 "user deletion success"
    fi
  done
}

setup_user_v2() {
  if [ $# -ne 3 ]; then
    log 2 "'setup_user_v2' requires role, number, bucket name"
    return 1
  fi
  if ! get_username_and_password "$1" "$2" "$3"; then
    log 2 "error getting username and password"
    return 1
  fi
  if [ "$AUTOGENERATE_USERS" == "true" ]; then
    if ! setup_user_versitygw_or_direct "$username" "$password" "$1" "$3"; then
      log 2 "error setting up user"
      return 1
    fi
  else
    echo "$user_id"
    echo "$username"
    echo "$password"
  fi
  return 0
}