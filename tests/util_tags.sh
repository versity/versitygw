#!/usr/bin/env bash

# params:  username, password, bucket, expected key, expected value
# return 0 for success, 1 for failure
get_and_check_bucket_tags_with_user() {
  log 6 "get_and_check_bucket_tags"
  if [ $# -ne 5 ]; then
    log 2 "'get_and_check_bucket_tags' requires username, password, bucket, expected key, expected value"
    return 1
  fi
  if ! get_bucket_tagging_with_user "$1" "$2" "$3"; then
    log 2 "error retrieving bucket tagging"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "TAGS: $tags"
  if ! tag=$(echo "$tags" | jq -r ".TagSet[0]" 2>&1); then
    log 2 "error getting tag: $tag"
    return 1
  fi
  if ! key=$(echo "$tag" | jq -r ".Key" 2>&1); then
    log 2 "error getting key: $key"
    return 1
  fi
  if [ "$key" != "$4" ]; then
    log 2 "key mismatch ($key, $4)"
    return 1
  fi
  if ! value=$(echo "$tag" | jq -r ".Value" 2>&1); then
    log 2 "error getting value: $value"
    return 1
  fi
  if [ "$value" != "$5" ]; then
    log 2 "value mismatch ($value, $5)"
    return 1
  fi
  return 0
}

# params:  bucket, expected tag key, expected tag value
# fail on error
get_and_check_bucket_tags() {
  assert [ $# -eq 3 ]
  run get_and_check_bucket_tags_with_user "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$1" "$2" "$3"
  assert_success "error getting and checking bucket tags"
  return 0
}

verify_no_bucket_tags() {
  if [ $# -ne 1 ]; then
    log 2 "'verify_no_bucket_tags' requires bucket name"
    return 1
  fi
  if ! get_bucket_tagging "$1"; then
    log 2 "error retrieving bucket tagging"
    return 1
  fi
  # shellcheck disable=SC2154
  if [[ "$tags" != "" ]]; then
    log 2 "tags should be empty, but are: $tags"
    return 1
  fi
  return 0
}
