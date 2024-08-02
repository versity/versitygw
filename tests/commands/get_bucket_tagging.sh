#!/usr/bin/env bash

# params:  client, bucket
# export 'tags' on success, return 1 for error
get_bucket_tagging() {
  log 6 "get_bucket_tagging"
  assert [ $# -eq 2 ]
  record_command "get-bucket-tagging" "client:$1"
  local result
  if [[ $1 == 'aws' ]]; then
    tags=$(aws --no-verify-ssl s3api get-bucket-tagging --bucket "$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(mc --insecure tag list "$MC_ALIAS"/"$2" 2>&1) || result=$?
  else
    fail "invalid command type $1"
  fi
  log 5 "Tags: $tags"
  tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  if [[ $result -ne 0 ]]; then
    if [[ $tags =~ "No tags found" ]] || [[ $tags =~ "The TagSet does not exist" ]]; then
      export tags=
      return 0
    fi
    echo "error getting bucket tags: $tags"
    return 1
  fi
  export tags
}

get_bucket_tagging_with_user() {
  log 6 "get_bucket_tagging_with_user"
  if [ $# -ne 3 ]; then
    log 2 "'get_bucket_tagging_with_user' command requires ID, key, bucket"
    return 1
  fi
  record_command "get-bucket-tagging" "client:s3api"
  local result
  if ! tags=$(AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" aws --no-verify-ssl s3api get-bucket-tagging --bucket "$3" 2>&1); then
    log 5 "tags error: $tags"
    if [[ $tags =~ "No tags found" ]] || [[ $tags =~ "The TagSet does not exist" ]]; then
      export tags=
      return 0
    fi
    fail "unrecognized error getting bucket tagging with user: $tags"
    return 1
  fi
  log 5 "raw tags data: $tags"
  tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  log 5 "modified tags data: $tags"
  return 0
}
