#!/usr/bin/env bash

get_bucket_policy() {
  if [[ $# -ne 2 ]]; then
    echo "get bucket policy command requires command type, bucket"
    return 1
  fi
  local get_bucket_policy_result=0
  if [[ $1 == 'aws' ]]; then
    get_bucket_policy_aws "$2" || get_bucket_policy_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_bucket_policy_s3cmd "$2" || get_bucket_policy_result=$?
  elif [[ $1 == 'mc' ]]; then
    get_bucket_policy_mc "$2" || get_bucket_policy_result=$?
  else
    echo "command 'get bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $get_bucket_policy_result -ne 0 ]]; then
    echo "error getting policy: $bucket_policy"
    return 1
  fi
  export bucket_policy
  return 0
}

get_bucket_policy_aws() {
  if [[ $# -ne 1 ]]; then
    echo "aws 'get bucket policy' command requires bucket"
    return 1
  fi
  policy_json=$(aws --no-verify-ssl s3api get-bucket-policy --bucket "$1" 2>&1) || get_result=$?
  if [[ $policy_json == *"InsecureRequestWarning"* ]]; then
    policy_json=$(awk 'NR>2' <<< "$policy_json")
  fi
  if [[ $get_result -ne 0 ]]; then
    if [[ "$policy_json" == *"(NoSuchBucketPolicy)"* ]]; then
      bucket_policy=
    else
      echo "error getting policy: $policy_json"
      return 1
    fi
  else
    bucket_policy=$(echo "{$policy_json}" | jq -r '.Policy')
  fi
  export bucket_policy
  return 0
}

get_bucket_policy_s3cmd() {
  if [[ $# -ne 1 ]]; then
    echo "s3cmd 'get bucket policy' command requires bucket"
    return 1
  fi

  info=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info "s3://$1") || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    echo "error getting bucket policy: $info"
    return 1
  fi

  bucket_policy=""
  policy_brackets=false
  while IFS= read -r line; do
    if [[ $policy_brackets == false ]]; then
      policy_line=$(echo "$line" | grep 'Policy: ')
      if [[ $policy_line != "" ]]; then
        if [[ $policy_line != *'{' ]]; then
          break
        fi
        policy_brackets=true
        bucket_policy+="{"
      fi
    else
      bucket_policy+=$line
      if [[ $line == "" ]]; then
        break
      fi
    fi
  done <<< "$info"
  export bucket_policy
  return 0
}

get_bucket_policy_mc() {
  if [[ $# -ne 1 ]]; then
    echo "aws 'get bucket policy' command requires bucket"
    return 1
  fi
  bucket_policy=$(mc --insecure anonymous get-json "$MC_ALIAS/$1") || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    echo "error getting policy: $bucket_policy"
    return 1
  fi
  export bucket_policy
  return 0
}