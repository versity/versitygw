#!/usr/bin/env bash

get_bucket_policy() {
  record_command "get-bucket-policy" "client:$1"
  if [[ $# -ne 2 ]]; then
    log 2 "get bucket policy command requires command type, bucket"
    return 1
  fi
  local get_bucket_policy_result=0
  if [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    get_bucket_policy_aws "$2" || get_bucket_policy_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    get_bucket_policy_s3cmd "$2" || get_bucket_policy_result=$?
  elif [[ $1 == 'mc' ]]; then
    get_bucket_policy_mc "$2" || get_bucket_policy_result=$?
  else
    log 2 "command 'get bucket policy' not implemented for '$1'"
    return 1
  fi
  if [[ $get_bucket_policy_result -ne 0 ]]; then
    log 2 "error getting policy: $bucket_policy"
    return 1
  fi
  export bucket_policy
  return 0
}

get_bucket_policy_aws() {
  record_command "get-bucket-policy" "client:s3api"
  if [[ $# -ne 1 ]]; then
    log 2 "aws 'get bucket policy' command requires bucket"
    return 1
  fi
  policy_json=$(aws --no-verify-ssl s3api get-bucket-policy --bucket "$1" 2>&1) || local get_result=$?
  policy_json=$(echo "$policy_json" | grep -v "InsecureRequestWarning")
  log 5 "$policy_json"
  if [[ $get_result -ne 0 ]]; then
    if [[ "$policy_json" == *"(NoSuchBucketPolicy)"* ]]; then
      bucket_policy=
    else
      log 2 "error getting policy: $policy_json"
      return 1
    fi
  else
    bucket_policy=$(echo "$policy_json" | jq -r '.Policy')
  fi
  export bucket_policy
  return 0
}

get_bucket_policy_with_user() {
  record_command "get-bucket-policy" "client:s3api"
  if [[ $# -ne 3 ]]; then
    log 2 "'get bucket policy with user' command requires bucket, username, password"
    return 1
  fi
  if policy_json=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" aws --no-verify-ssl s3api get-bucket-policy --bucket "$1" 2>&1); then
    policy_json=$(echo "$policy_json" | grep -v "InsecureRequestWarning")
    bucket_policy=$(echo "$policy_json" | jq -r '.Policy')
  else
    if [[ "$policy_json" == *"(NoSuchBucketPolicy)"* ]]; then
      bucket_policy=
    else
      log 2 "error getting policy for user $2: $policy_json"
      return 1
    fi
  fi
  export bucket_policy
  return 0
}

get_bucket_policy_s3cmd() {
  record_command "get-bucket-policy" "client:s3cmd"
  if [[ $# -ne 1 ]]; then
    log 2 "s3cmd 'get bucket policy' command requires bucket"
    return 1
  fi

  if ! info=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate info "s3://$1" 2>&1); then
    log 2 "error getting bucket policy: $info"
    return 1
  fi

  log 5 "policy info: $info"
  bucket_policy=""
  policy_brackets=false
  # NOTE:  versitygw sends policies back in multiple lines here, direct in single line
  while IFS= read -r line; do
    if [[ $policy_brackets == false ]]; then
      policy_line=$(echo "$line" | grep 'Policy: ')
      if [[ $policy_line != "" ]]; then
        if [[ $policy_line != *'{'* ]]; then
          break
        fi
        if [[ $policy_line == *'}'* ]]; then
          log 5 "policy on single line"
          bucket_policy=${policy_line//Policy:/}
          break
        else
          policy_brackets=true
          bucket_policy+="{"
        fi
      fi
    else
      bucket_policy+=$line
      if [[ $line == "" ]]; then
        break
      fi
    fi
  done <<< "$info"
  log 5 "bucket policy: $bucket_policy"
  export bucket_policy
  return 0
}

get_bucket_policy_mc() {
  record_command "get-bucket-policy" "client:mc"
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