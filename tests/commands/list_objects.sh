#!/usr/bin/env bash

# args: client, bucket name
# fail if unable to list
list_objects() {
  log 6 "list_objects"
  record_command "list-objects" "client:$1"
  assert [ $# -eq 2 ]

  if [[ $1 == "aws" ]] || [[ $1 == 's3' ]]; then
    run aws --no-verify-ssl s3 ls s3://"$2"
  elif [[ $1 == 's3api' ]]; then
    list_objects_s3api "$2"
    return 0
  elif [[ $1 == 's3cmd' ]]; then
    run s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2"
  elif [[ $1 == 'mc' ]]; then
    run mc --insecure ls "$MC_ALIAS"/"$2"
  else
    fail "invalid command type $1"
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
  assert [ $# -eq 1 ]
  run aws --no-verify-ssl s3api list-objects --bucket "$1"
  assert_success "error listing objects: $output"

  log 5 "list_objects_s3api: raw data returned: $output"
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