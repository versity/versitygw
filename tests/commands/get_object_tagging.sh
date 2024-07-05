#!/usr/bin/env bash

get_object_tagging() {
  record_command "get-object-tagging" "client:$1"
  if [ $# -ne 3 ]; then
    log 2 "get object tag command missing command type, bucket, and/or key"
    return 1
  fi
  local result
  if [[ $1 == 'aws' ]]; then
    tags=$(aws --no-verify-ssl s3api get-object-tagging --bucket "$2" --key "$3" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(mc --insecure tag list "$MC_ALIAS"/"$2"/"$3" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    if [[ "$tags" == *"NoSuchTagSet"* ]] || [[ "$tags" == *"No tags found"* ]]; then
      tags=
    else
      log 2 "error getting object tags: $tags"
      return 1
    fi
  else
    log 5 "$tags"
    tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  fi
  export tags
}