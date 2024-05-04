#!/usr/bin/env bash

source ./tests/util_bucket_create.sh
source ./tests/util_mc.sh
source ./tests/logger.sh
source ./tests/commands/abort_multipart_upload.sh
source ./tests/commands/create_bucket.sh
source ./tests/commands/delete_bucket.sh
source ./tests/commands/delete_object.sh
source ./tests/commands/get_bucket_tagging.sh
source ./tests/commands/head_bucket.sh
source ./tests/commands/head_object.sh
source ./tests/commands/list_objects.sh

# recursively delete an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket_recursive() {
  if [ $# -ne 2 ]; then
    log 2 "delete bucket missing command type, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 rb s3://"$2" --force 2>&1) || exit_code="$?"
  elif [[ $1 == "aws" ]] || [[ $1 == 's3api' ]]; then
    delete_bucket_recursive_s3api "$2" 2>&1 || exit_code="$?"
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rb s3://"$2" --recursive 2>&1) || exit_code="$?"
  elif [[ $1 == "mc" ]]; then
    error=$(delete_bucket_recursive_mc "$2") || exit_code="$?"
  else
    log 2 "invalid command type '$1'"
    return 1
  fi

  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    else
      log 2 "error deleting bucket recursively: $error"
      return 1
    fi
  fi
  return 0
}

delete_bucket_recursive_s3api() {
  if [[ $# -ne 1 ]]; then
    echo "delete bucket recursive command for s3api requires bucket name"
    return 1
  fi
  list_objects 's3api' "$1" || list_result=$?
  if [[ $list_result -ne 0 ]]; then
    echo "error listing objects"
    return 1
  fi
  # shellcheck disable=SC2154
  for object in "${object_array[@]}"; do
    delete_object 's3api' "$1" "$object" || delete_result=$?
    if [[ $delete_result -ne 0 ]]; then
      echo "error deleting object $object"
      return 1
    fi
  done

  delete_bucket 's3api' "$1" || delete_result=$?
  if [[ $delete_result -ne 0 ]]; then
    echo "error deleting bucket"
    return 1
  fi
  return 0
}

# delete contents of a bucket
# param:  command type, bucket name
# return 0 for success, 1 for failure
delete_bucket_contents() {
  if [ $# -ne 2 ]; then
    log 2 "delete bucket missing command id, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == "aws" ]] || [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3 rm s3://"$2" --recursive 2>&1) || exit_code="$?"
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate del s3://"$2" --recursive --force 2>&1) || exit_code="$?"
  elif [[ $1 == "mc" ]]; then
    error=$(mc --insecure rm --force --recursive "$MC_ALIAS"/"$2" 2>&1) || exit_code="$?"
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    log 2 "error deleting bucket contents: $error"
    return 1
  fi
  return 0
}

# check if bucket exists
# param:  bucket name
# return 0 for true, 1 for false, 2 for error
bucket_exists() {
  if [ $# -ne 2 ]; then
    echo "bucket exists check missing command type, bucket name"
    return 2
  fi

  head_bucket "$1" "$2" || local check_result=$?
  if [[ $check_result -ne 0 ]]; then
    # shellcheck disable=SC2154
    if [[ "$bucket_info" == *"404"* ]] || [[ "$bucket_info" == *"does not exist"* ]]; then
      return 1
    fi
    echo "error checking if bucket exists"
    return 2
  fi
  return 0
}

# delete buckets or just the contents depending on RECREATE_BUCKETS parameter
# params:  command type, bucket name
# return:  0 for success, 1 for failure
delete_bucket_or_contents() {
  if [ $# -ne 2 ]; then
    echo "delete bucket or contents function requires command type, bucket name"
    return 1
  fi
  if [[ $RECREATE_BUCKETS == "false" ]]; then
    delete_bucket_contents "$1" "$2" || local delete_result=$?
    if [[ $delete_result -ne 0 ]]; then
      echo "error deleting bucket contents"
      return 1
    fi
    return 0
  fi
  delete_bucket_recursive "$1" "$2" || local delete_result=$?
  if [[ $delete_result -ne 0 ]]; then
    echo "Bucket deletion error"
    return 1
  fi
  return 0
}

# if RECREATE_BUCKETS is set to true create bucket, deleting it if it exists to clear state.  If not,
# check to see if it exists and return an error if it does not.
# param:  bucket name
# return 0 for success, 1 for failure
setup_bucket() {
  if [ $# -ne 2 ]; then
    echo "bucket creation function requires command type, bucket name"
    return 1
  fi
  local exists_result
  bucket_exists "$1" "$2" || exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    echo "Bucket existence check error"
    return 1
  fi
  if [[ $exists_result -eq 0 ]]; then
    delete_bucket_or_contents "$1" "$2" || delete_result=$?
    if [[ delete_result -ne 0 ]]; then
      echo "error deleting bucket or contents"
      return 1
    fi
    if [[ $RECREATE_BUCKETS == "false" ]]; then
      echo "bucket data deletion success"
      return 0
    fi
  fi
  if [[ $exists_result -eq 1 ]] && [[ $RECREATE_BUCKETS == "false" ]]; then
    echo "When RECREATE_BUCKETS isn't set to \"true\", buckets should be pre-created by user"
    return 1
  fi
  local create_result
  create_bucket "$1" "$2" || create_result=$?
  if [[ $create_result -ne 0 ]]; then
    echo "Error creating bucket"
    return 1
  fi
  echo "Bucket creation success"
  return 0
}

# check if object exists on S3 via gateway
# param:  command, object path
# return 0 for true, 1 for false, 2 for error
object_exists() {
  if [ $# -ne 3 ]; then
    echo "object exists check missing command, bucket name, object name"
    return 2
  fi
  head_object "$1" "$2" "$3" || head_result=$?
  if [[ $head_result -eq 2 ]]; then
    echo "error checking if object exists"
    return 2
  fi
  return $head_result

  return 0
  local exit_code=0
  local error=""
  if [[ $1 == 's3' ]]; then
    error=$(aws --no-verify-ssl s3 ls "s3://$2/$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 'aws' ]] || [[ $1 == 's3api' ]]; then
    error=$(aws --no-verify-ssl s3api head-object --bucket "$2" --prefix "$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2/$3" 2>&1) || exit_code="$?"
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure ls "$MC_ALIAS/$2/$3" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 2
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == "" ]] || [[ $error == *"InsecureRequestWarning"* ]]; then
      return 1
    else
      echo "error checking if object exists: $error"
      return 2
    fi
  # s3cmd, mc return empty when object doesn't exist, rather than error
  elif [[ ( $1 == 's3cmd' ) || ( $1 == 'mc' ) ]] && [[ $error == "" ]]; then
    return 1
  fi
  return 0
}

put_object_with_metadata() {
  if [ $# -ne 6 ]; then
    echo "put object command requires command type, source, destination, key, metadata key, metadata value"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-object --body "$2" --bucket "$3" --key "$4" --metadata "{\"$5\":\"$6\"}") || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  log 5 "put object exit code: $exit_code"
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  return 0
}

get_object_metadata() {
  if [ $# -ne 3 ]; then
    echo "get object metadata command requires command type, bucket, key"
    return 1
  fi

  local exit_code=0
  if [[ $1 == 'aws' ]]; then
    metadata_struct=$(aws --no-verify-ssl s3api head-object --bucket "$2" --key "$3") || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  log 5 "$metadata_struct"
  metadata=$(echo "$metadata_struct" | jq '.Metadata')
  echo $metadata
  export metadata
  return 0
}

put_object_multiple() {
  if [ $# -ne 3 ]; then
    echo "put object command requires command type, source, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 'aws' ]] || [[ $1 == 's3' ]]; then
    # shellcheck disable=SC2086
    error=$(aws --no-verify-ssl s3 cp "$(dirname "$2")" s3://"$3" --recursive --exclude="*" --include="$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    # shellcheck disable=SC2086
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put $2 "s3://$3/" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    # shellcheck disable=SC2086
    error=$(mc --insecure cp $2 "$MC_ALIAS"/"$3" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  else
    log 5 "$error"
  fi
  return 0
}

# add object to versitygw if it doesn't exist
# params:  source file, destination copy location
# return 0 for success or already exists, 1 for failure
check_and_put_object() {
  if [ $# -ne 3 ]; then
    echo "check and put object function requires source, bucket, destination"
    return 1
  fi
  object_exists "aws" "$2" "$3" || local exists_result=$?
  if [ "$exists_result" -eq 2 ]; then
    echo "error checking if object exists"
    return 1
  fi
  if [ "$exists_result" -eq 1 ]; then
    copy_object "$1" "$2" || local copy_result=$?
    if [ "$copy_result" -ne 0 ]; then
      echo "error adding object"
      return 1
    fi
  fi
  return 0
}

list_buckets_with_user() {
  if [[ $# -ne 3 ]]; then
    echo "List buckets command missing format, user id, key"
    return 1
  fi

  local exit_code=0
  local output
  if [[ $1 == "aws" ]]; then
    output=$(AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" aws --no-verify-ssl s3 ls s3:// 2>&1) || exit_code=$?
  else
    echo "invalid format:  $1"
    return 1
  fi

  if [ $exit_code -ne 0 ]; then
    echo "error listing buckets: $output"
    return 1
  fi

  bucket_array=()
  while IFS= read -r line; do
    bucket_name=$(echo "$line" | awk '{print $NF}')
    bucket_array+=("${bucket_name%/}")
  done <<< "$output"

  export bucket_array
}

remove_insecure_request_warning() {
  if [[ $# -ne 1 ]]; then
    echo "remove insecure request warning requires input lines"
    return 1
  fi
  parsed_output=()
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      parsed_output+=("$line")
    fi
  done <<< "$1"
  export parsed_output
}

# check if bucket info can be retrieved
# param:  path of bucket or folder
# return 0 for yes, 1 for no, 2 for error
bucket_is_accessible() {
  if [ $# -ne 1 ]; then
    echo "bucket accessibility check missing bucket name"
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws --no-verify-ssl s3api head-bucket --bucket "$1" 2>&1) || exit_code="$?"
  if [ $exit_code -eq 0 ]; then
    return 0
  fi
  if [[ "$error" == *"500"* ]]; then
    return 1
  fi
  echo "Error checking bucket accessibility: $error"
  return 2
}

# check if object info (etag) is accessible
# param:  path of object
# return 0 for yes, 1 for no, 2 for error
object_is_accessible() {
  if [ $# -ne 2 ]; then
    echo "object accessibility check missing bucket and/or key"
    return 2
  fi
  local exit_code=0
  object_data=$(aws --no-verify-ssl s3api head-object --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "Error obtaining object data: $object_data"
    return 2
  fi
  etag=$(echo "$object_data" | grep -v "InsecureRequestWarning" | jq '.ETag')
  if [[ "$etag" == '""' ]]; then
    return 1
  fi
  return 0
}

# get object acl
# param:  object path
# export acl for success, return 1 for error
get_object_acl() {
  if [ $# -ne 2 ]; then
    echo "object ACL command missing object name"
    return 1
  fi
  local exit_code=0
  acl=$(aws --no-verify-ssl s3api get-object-acl --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "Error getting object ACLs: $acl"
    return 1
  fi
  export acl
}

# add tags to bucket
# params:  bucket, key, value
# return:  0 for success, 1 for error
put_bucket_tag() {
  if [ $# -ne 4 ]; then
    echo "bucket tag command missing command type, bucket name, key, value"
    return 1
  fi
  local error
  local result
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-bucket-tagging --bucket "$2" --tagging "TagSet=[{Key=$3,Value=$4}]") || result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure tag set "$MC_ALIAS"/"$2" "$3=$4" 2>&1) || result=$?
  else
    log 2 "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    echo "Error adding bucket tag: $error"
    return 1
  fi
  return 0
}



check_tags_empty() {
  if [[ $# -ne 1 ]]; then
    echo "check tags empty requires command type"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    if [[ $tags != "" ]]; then
      tag_set=$(echo "$tags" | jq '.TagSet')
      if [[ $tag_set != "[]" ]]; then
        echo "error:  tags not empty: $tags"
        return 1
      fi
    fi
  else
    if [[ $tags != "" ]] && [[ $tags != *"No tags found"* ]]; then
      echo "Error:  tags not empty: $tags"
      return 1
    fi
  fi
  return 0
}

check_object_tags_empty() {
  if [[ $# -ne 3 ]]; then
    echo "bucket tags empty check requires command type, bucket, and key"
    return 2
  fi
  get_object_tags "$1" "$2" "$3" || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    echo "failed to get tags"
    return 2
  fi
  check_tags_empty "$1" || local check_result=$?
  return $check_result
}

check_bucket_tags_empty() {
  if [[ $# -ne 2 ]]; then
    echo "bucket tags empty check requires command type, bucket"
    return 2
  fi
  get_bucket_tagging "$1" "$2" || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    echo "failed to get tags"
    return 2
  fi
  check_tags_empty "$1" || local check_result=$?
  return $check_result
}

delete_bucket_tags() {
  if [ $# -ne 2 ]; then
    echo "delete bucket tag command missing command type, bucket name"
    return 1
  fi
  local result
  if [[ $1 == 'aws' ]]; then
    tags=$(aws --no-verify-ssl s3api delete-bucket-tagging --bucket "$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(mc --insecure tag remove "$MC_ALIAS"/"$2" 2>&1) || result=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  return 0
}

# add tags to object
# params:  object, key, value
# return:  0 for success, 1 for error
put_object_tag() {
  if [ $# -ne 5 ]; then
    echo "object tag command missing command type, object name, file, key, and/or value"
    return 1
  fi
  local error
  local result
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api put-object-tagging --bucket "$2" --key "$3" --tagging "TagSet=[{Key=$4,Value=$5}]" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure tag set "$MC_ALIAS"/"$2"/"$3" "$4=$5" 2>&1) || result=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    echo "Error adding object tag: $error"
    return 1
  fi
  return 0
}

get_and_verify_object_tags() {
  if [[ $# -ne 5 ]]; then
    echo "get and verify object tags missing command type, bucket, key, tag key, tag value"
    return 1
  fi
  get_object_tags "$1" "$2" "$3" || get_result=$?
  if [[ $get_result -ne 0 ]]; then
    echo "failed to get tags"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    tag_set_key=$(echo "$tags" | jq '.TagSet[0].Key')
    tag_set_value=$(echo "$tags" | jq '.TagSet[0].Value')
    if [[ $tag_set_key != '"'$4'"' ]]; then
      echo "Key mismatch ($tag_set_key, \"$4\")"
      return 1
    fi
    if [[ $tag_set_value != '"'$5'"' ]]; then
      echo "Value mismatch ($tag_set_value, \"$5\")"
      return 1
    fi
  else
    read -r tag_set_key tag_set_value <<< "$(echo "$tags" | awk 'NR==2 {print $1, $3}')"
    [[ $tag_set_key == "$4" ]] || fail "Key mismatch"
    [[ $tag_set_value == "$5" ]] || fail "Value mismatch"
  fi
  return 0
}

# get object tags
# params:  bucket
# export 'tags' on success, return 1 for error
get_object_tags() {
  if [ $# -ne 3 ]; then
    echo "get object tag command missing command type, bucket, and/or key"
    return 1
  fi
  local result
  if [[ $1 == 'aws' ]]; then
    tags=$(aws --no-verify-ssl s3api get-object-tagging --bucket "$2" --key "$3" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(mc --insecure tag list "$MC_ALIAS"/"$2"/"$3" 2>&1) || result=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    if [[ "$tags" == *"NoSuchTagSet"* ]] || [[ "$tags" == *"No tags found"* ]]; then
      tags=
    else
      echo "error getting object tags: $tags"
      return 1
    fi
  else
    log 5 "$tags"
    tags=$(echo "$tags" | grep -v "InsecureRequestWarning")
  fi
  export tags
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

# list objects in bucket, v2
# param:  bucket
# export objects on success, return 1 for failure
list_objects_s3api_v2() {
  if [ $# -ne 1 ]; then
    echo "list objects command missing bucket and/or path"
    return 1
  fi
  objects=$(aws --no-verify-ssl s3api list-objects-v2 --bucket "$1") || local result=$?
  if [[ $result -ne 0 ]]; then
    echo "error listing objects: $objects"
    return 1
  fi
  export objects
}

# initialize a multipart upload
# params:  bucket, key
# return 0 for success, 1 for failure
create_multipart_upload() {
  if [ $# -ne 2 ]; then
    echo "create multipart upload function must have bucket, key"
    return 1
  fi

  local multipart_data
  multipart_data=$(aws --no-verify-ssl s3api create-multipart-upload --bucket "$1" --key "$2") || local created=$?
  if [[ $created -ne 0 ]]; then
    echo "Error creating multipart upload: $upload_id"
    return 1
  fi

  upload_id=$(echo "$multipart_data" | jq '.UploadId')
  upload_id="${upload_id//\"/}"
  export upload_id
}

# upload a single part of a multipart upload
# params: bucket, key, upload ID, original (unsplit) file name, part number
# return: 0 for success, 1 for failure
upload_part() {
  if [ $# -ne 5 ]; then
    echo "upload multipart part function must have bucket, key, upload ID, file name, part number"
    return 1
  fi
  local etag_json
  etag_json=$(aws --no-verify-ssl s3api upload-part --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --body "$4-$(($5-1))") || local uploaded=$?
  if [[ $uploaded -ne 0 ]]; then
    echo "Error uploading part $5: $etag_json"
    return 1
  fi
  etag=$(echo "$etag_json" | jq '.ETag')
  export etag
}

# perform all parts of a multipart upload before completion command
# params:  bucket, key, file to split and upload, number of file parts to upload
# return:  0 for success, 1 for failure
multipart_upload_before_completion() {
  if [ $# -ne 4 ]; then
    echo "multipart upload pre-completion command missing bucket, key, file, and/or part count"
    return 1
  fi

  split_file "$3" "$4" || split_result=$?
  if [[ $split_result -ne 0 ]]; then
    echo "error splitting file"
    return 1
  fi

  create_multipart_upload "$1" "$2" || create_result=$?
  if [[ $create_result -ne 0 ]]; then
    echo "error creating multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    upload_part "$1" "$2" "$upload_id" "$3" "$i" || local upload_result=$?
    if [[ $upload_result -ne 0 ]]; then
      echo "error uploading part $i"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  export parts
}

# perform a multi-part upload
# params:  bucket, key, source file location, number of parts
# return 0 for success, 1 for failure
multipart_upload() {
  if [ $# -ne 4 ]; then
    echo "multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  multipart_upload_before_completion "$1" "$2" "$3" "$4" || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error performing pre-completion multipart upload"
    return 1
  fi

  error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}') || local completed=$?
  if [[ $completed -ne 0 ]]; then
    echo "Error completing upload: $error"
    return 1
  fi
  return 0
}

# run upload, then abort it
# params:  bucket, key, local file location, number of parts to split into before uploading
# return 0 for success, 1 for failure
run_then_abort_multipart_upload() {
  if [ $# -ne 4 ]; then
    echo "run then abort multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  multipart_upload_before_completion "$1" "$2" "$3" "$4" || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error performing pre-completion multipart upload"
    return 1
  fi

  abort_multipart_upload "$1" "$2" "$upload_id"
  return $?
}

# copy a file to/from S3
# params:  source, destination
# return 0 for success, 1 for failure
copy_file() {
  if [ $# -ne 2 ]; then
    echo "copy file command requires src and dest"
    return 1
  fi

  local result
  error=$(aws --no-verify-ssl s3 cp "$1" "$2") || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error copying file: $error"
    return 1
  fi
  return 0
}

# list parts of an unfinished multipart upload
# params:  bucket, key, local file location, and parts to split into before upload
# export parts on success, return 1 for error
list_parts() {
  if [ $# -ne 4 ]; then
    echo "list multipart upload parts command missing bucket, key, file, and/or part count"
    return 1
  fi

  multipart_upload_before_completion "$1" "$2" "$3" "$4" || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error performing pre-completion multipart upload"
    return 1
  fi

  listed_parts=$(aws --no-verify-ssl s3api list-parts --bucket "$1" --key "$2" --upload-id "$upload_id") || local listed=$?
  if [[ $listed -ne 0 ]]; then
    echo "Error aborting upload: $parts"
    return 1
  fi
  export listed_parts
}

# list unfinished multipart uploads
# params:  bucket, key one, key two
# export current two uploads on success, return 1 for error
list_multipart_uploads() {
  if [ $# -ne 3 ]; then
    echo "list multipart uploads command requires bucket and two keys"
    return 1
  fi

  create_multipart_upload "$1" "$2" || local create_result=$?
  if [[ $create_result -ne 0 ]]; then
    echo "error creating multpart upload"
    return 1
  fi

  create_multipart_upload "$1" "$3" || local create_result_two=$?
  if [[ $create_result_two -ne 0 ]]; then
    echo "error creating multpart upload two"
    return 1
  fi

  uploads=$(aws --no-verify-ssl s3api list-multipart-uploads --bucket "$1") || local list_result=$?
  if [[ $list_result -ne 0 ]]; then
    echo "error listing uploads: $uploads"
    return 1
  fi
  export uploads
}

# perform a multi-part upload within bucket
# params:  bucket, key, file, number of parts
# return 0 for success, 1 for failure
multipart_upload_from_bucket() {
  if [ $# -ne 4 ]; then
    echo "multipart upload from bucket command missing bucket, copy source, key, and/or part count"
    return 1
  fi

  split_file "$3" "$4" || split_result=$?
  if [[ $split_result -ne 0 ]]; then
    echo "error splitting file"
    return 1
  fi

  for ((i=0;i<$4;i++)) {
    echo "key: $3"
    put_object "s3api" "$3-$i" "$1" "$2-$i" || copy_result=$?
    if [[ $copy_result -ne 0 ]]; then
      echo "error copying object"
      return 1
    fi
  }

  create_multipart_upload "$1" "$2-copy" || upload_result=$?
  if [[ $upload_result -ne 0 ]]; then
    echo "error running first multpart upload"
    return 1
  fi

  parts="["
  for ((i = 1; i <= $4; i++)); do
    upload_part_copy "$1" "$2-copy" "$upload_id" "$2" "$i" || local upload_result=$?
    if [[ $upload_result -ne 0 ]]; then
      echo "error uploading part $i"
      return 1
    fi
    parts+="{\"ETag\": $etag, \"PartNumber\": $i}"
    if [[ $i -ne $4 ]]; then
      parts+=","
    fi
  done
  parts+="]"

  error=$(aws --no-verify-ssl s3api complete-multipart-upload --bucket "$1" --key "$2-copy" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}') || local completed=$?
    if [[ $completed -ne 0 ]]; then
      echo "Error completing upload: $error"
      return 1
    fi
    return 0

  parts+="]"
}

upload_part_copy() {
  if [ $# -ne 5 ]; then
    echo "upload multipart part copy function must have bucket, key, upload ID, file name, part number"
    return 1
  fi
  local etag_json
  echo "$1 $2 $3 $4 $5"
  etag_json=$(aws --no-verify-ssl s3api upload-part-copy --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --copy-source "$1/$4-$(($5-1))") || local uploaded=$?
  if [[ $uploaded -ne 0 ]]; then
    echo "Error uploading part $5: $etag_json"
    return 1
  fi
  etag=$(echo "$etag_json" | jq '.CopyPartResult.ETag')
  export etag
}

create_presigned_url() {
  if [[ $# -ne 3 ]]; then
    echo "create presigned url function requires command type, bucket, and filename"
    return 1
  fi

  local presign_result=0
  if [[ $1 == 'aws' ]]; then
    presigned_url=$(aws s3 presign "s3://$2/$3" --expires-in 900) || presign_result=$?
  elif [[ $1 == 's3cmd' ]]; then
    presigned_url=$(s3cmd --no-check-certificate "${S3CMD_OPTS[@]}" signurl "s3://$2/$3" "$(echo "$(date +%s)" + 900 | bc)") || presign_result=$?
  elif [[ $1 == 'mc' ]]; then
    presigned_url_data=$(mc --insecure share download --recursive "$MC_ALIAS/$2/$3") || presign_result=$?
    presigned_url="${presigned_url_data#*Share: }"
  else
    echo "unrecognized command type $1"
    return 1
  fi
  if [[ $presign_result -ne 0 ]]; then
    echo "error generating presigned url: $presigned_url"
    return 1
  fi
  export presigned_url
}
