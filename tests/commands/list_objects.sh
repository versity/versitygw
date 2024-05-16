#!/usr/bin/env bash

list_objects() {
  if [ $# -ne 2 ]; then
    echo "list objects command requires command type, and bucket or folder"
    return 1
  fi
  local exit_code=0
  local output
  if [[ $1 == "aws" ]] || [[ $1 == 's3' ]]; then
    output=$(aws --no-verify-ssl s3 ls s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3api' ]]; then
    list_objects_s3api "$2" || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    output=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    output=$(mc --insecure ls "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error listing objects: $output"
    return 1
  fi

  if [[ $1 == 's3api' ]]; then
    return 0
  fi

  object_array=()
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      object_name=$(echo "$line" | awk '{print $NF}')
      object_array+=("$object_name")
    fi
  done <<< "$output"

  export object_array
}

list_objects_s3api() {
  if [[ $# -ne 1 ]]; then
    echo "list objects s3api command requires bucket name"
    return 1
  fi
  output=$(aws --no-verify-ssl s3api list-objects --bucket "$1" 2>&1) || local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    echo "error listing objects: $output"
    return 1
  fi

  modified_output=""
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      modified_output+="$line"
    fi
  done <<< "$output"

  object_array=()
  log 5 "modified output: $modified_output"
  if echo "$modified_output" | jq -e 'has("Contents")'; then
    contents=$(echo "$modified_output" | jq -r '.Contents[]')
    log 5 "contents: $contents"
    keys=$(echo "$contents" | jq -r '.Key')
    IFS=$'\n' read -rd '' -a object_array <<<"$keys"
  fi

  export object_array
}