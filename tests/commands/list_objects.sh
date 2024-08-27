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

# list objects in bucket, v1
# param:  bucket
# export objects on success, return 1 for failure
list_objects_s3api_v1() {
  if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "list objects command requires bucket, (optional) delimiter"
    return 1
  fi
  if [ "$2" == "" ]; then
    objects=$(aws --no-verify-ssl s3api list-objects --bucket "$1") || local result=$?
  else
    objects=$(aws --no-verify-ssl s3api list-objects --bucket "$1" --delimiter "$2") || local result=$?
  fi
  if [[ $result -ne 0 ]]; then
    echo "error listing objects: $objects"
    return 1
  fi
  export objects
}

list_objects_with_prefix() {
  if [ $# -ne 3 ]; then
    log 2 "'list_objects_with_prefix' command requires, client, bucket, prefix"
    return 1
  fi
  local result=0
  if [ "$1" == 's3' ]; then
    objects=$(aws --no-verify-ssl s3 ls s3://"$2/$3" 2>&1) || result=$?
  elif [ "$1" == 's3api' ]; then
    objects=$(aws --no-verify-ssl s3api list-objects --bucket "$2" --prefix "$3" 2>&1) || result=$?
  elif [ "$1" == 's3cmd' ]; then
    objects=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2/$3" 2>&1) || result=$?
  elif [[ "$1" == 'mc' ]]; then
    objects=$(mc --insecure ls "$MC_ALIAS/$2/$3" 2>&1) || result=$?
  else
    log 2 "invalid command type '$1'"
    return 1
  fi
  if [ $result -ne 0 ]; then
    log 2 "error listing objects: $objects"
    return 1
  fi
  log 5 "output: $objects"
  export objects
  return 0
}
