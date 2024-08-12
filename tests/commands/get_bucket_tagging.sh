#!/usr/bin/env bash

# get bucket tags
# params:  bucket
# export 'tags' on success, return 1 for error
get_bucket_tagging() {
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