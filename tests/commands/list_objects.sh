#!/usr/bin/env bash

# args: client, bucket name
# return 0 if able to list, 1 if not
list_objects() {
  log 6 "list_objects"
  record_command "list-objects" "client:$1"
  if [ $# -ne 2 ]; then
    log 2 "'list_objects' command requires client, bucket"
    return 1
  fi

  local output
  local result=0
  if [[ $1 == "aws" ]] || [[ $1 == 's3' ]]; then
    output=$(aws --no-verify-ssl s3 ls s3://"$2" 2>&1) || result=$?
  elif [[ $1 == 's3api' ]]; then
    list_objects_s3api "$2" || result=$?
    return $result
  elif [[ $1 == 's3cmd' ]]; then
    output=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    output=$(mc --insecure ls "$MC_ALIAS"/"$2" 2>&1) || result=$?
  else
    fail "invalid command type $1"
    return 1
  fi
  # shellcheck disable=SC2154
  assert_success "error listing objects: $output"

  object_array=()
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      object_name=$(echo "$line" | awk '{print $NF}')
      object_array+=("$object_name")
    fi
  done <<< "$output"

  export object_array
}

# args: bucket name
# fail if unable to list
list_objects_s3api() {
  log 6 "list_objects_s3api"
  if [ $# -ne 1 ]; then
    log 2 "'list_objects_s3api' requires bucket"
    return 1
  fi
  if ! output=$(aws --no-verify-ssl s3api list-objects --bucket "$1" 2>&1); then
    log 2 "error listing objects: $output"
    return 1
  fi

  log 5 "list_objects_s3api: raw data returned: $output"
  modified_output=$(echo "$output" | grep -v "InsecureRequestWarning")

  object_array=()
  log 5 "modified output: $modified_output"
  if echo "$modified_output" | jq -e 'has("Contents")'; then
    contents=$(echo "$modified_output" | jq -r '.Contents[]')
    log 5 "contents: $contents"
    keys=$(echo "$contents" | jq -r '.Key')
    IFS=$'\n' read -rd '' -a object_array <<<"$keys"
  fi
  return 0
}