#!/usr/bin/env bats

source ./tests/util_mc.sh
source ./tests/logger.sh

# create an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
create_bucket() {
  if [ $# -ne 2 ]; then
    echo "create bucket missing command type, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == "aws" ]]; then
    error=$(aws --no-verify-ssl s3 mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == "mc" ]]; then
    error=$(mc --insecure mb "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error creating bucket: $error"
    return 1
  fi
  return 0
}

create_bucket_invalid_name() {
  if [ $# -ne 1 ]; then
    echo "create bucket w/invalid name missing command type"
    return 1
  fi
  local exit_code=0
  if [[ $1 == "aws" ]]; then
    bucket_create_error=$(aws --no-verify-ssl s3 mb "s3://" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    bucket_create_error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate mb "s3://" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    bucket_create_error=$(mc --insecure mb "$MC_ALIAS" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -eq 0 ]; then
    echo "error:  bucket should have not been created but was"
    return 1
  fi
  export bucket_create_error
}

# delete an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket() {
  if [ $# -ne 2 ]; then
    echo "delete bucket missing command type, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3 rb s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure rb "$MC_ALIAS/$2" 2>&1) || exit_code=$?
  else
    echo "Invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    else
      echo "error deleting bucket: $error"
      return 1
    fi
  fi
  return 0
}

# recursively delete an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket_recursive() {
  if [ $# -ne 2 ]; then
    echo "delete bucket missing command type, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == "aws" ]]; then
    error=$(aws --no-verify-ssl s3 rb s3://"$2" --force 2>&1) || exit_code="$?"
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rb s3://"$2" --recursive 2>&1) || exit_code="$?"
  elif [[ $1 == "mc" ]]; then
    error=$(delete_bucket_recursive_mc "$2") || exit_code="$?"
  else
    echo "invalid command type '$1'"
    return 1
  fi

  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]]; then
      return 0
    else
      echo "error deleting bucket recursively: $error"
      return 1
    fi
  fi
  return 0
}

# delete contents of a bucket
# param:  command type, bucket name
# return 0 for success, 1 for failure
delete_bucket_contents() {
  if [ $# -ne 2 ]; then
    echo "delete bucket missing command id, bucket name"
    return 1
  fi

  local exit_code=0
  local error
  if [[ $1 == "aws" ]]; then
    error=$(aws --no-verify-ssl s3 rm s3://"$2" --recursive 2>&1) || exit_code="$?"
  elif [[ $1 == "s3cmd" ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate del s3://"$2" --recursive --force 2>&1) || exit_code="$?"
  elif [[ $1 == "mc" ]]; then
    error=$(mc --insecure rm --force --recursive "$MC_ALIAS"/"$2" 2>&1) || exit_code="$?"
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error deleting bucket contents: $error"
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

  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3 ls s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    # NOTE:  s3cmd sometimes takes longer with direct connection
    sleep 1
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure ls "$MC_ALIAS/$2" 2>&1) || exit_code=$?
  else
    echo "invalid command type: $1"
    return 2
  fi

  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"does not exist"* ]] || [[ "$error" == *"Access Denied"* ]]; then
      return 1
    else
      echo "error checking if bucket exists: $error"
      return 2
    fi
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
  if [ $# -ne 2 ]; then
    echo "object exists check missing command, object name"
    return 2
  fi
  local exit_code=0
  local error=""
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3 ls s3://"$2" 2>&1) || exit_code="$?"
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3://"$2" 2>&1) || exit_code="$?"
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure ls "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
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

# add object to versitygw
# params:  source file, destination copy location
# return 0 for success, 1 for failure
put_object() {
  if [ $# -ne 3 ]; then
    echo "put object command requires command type, source, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3 cp "$2" s3://"$3" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate put "$2" s3://"$(dirname "$3")" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure cp "$2" "$MC_ALIAS"/"$(dirname "$3")" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
  fi
  return 0
}

put_object_multiple() {
  if [ $# -ne 3 ]; then
    echo "put object command requires command type, source, destination"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
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
  if [ $# -ne 2 ]; then
    echo "check and put object function requires source, destination"
    return 1
  fi
  object_exists "aws" "$2" || local exists_result=$?
  if [ "$exists_result" -eq 2 ]; then
    echo "error checking if object exists"
    return 1
  fi
  if [ "$exists_result" -eq 1 ]; then
    put_object "$1" "$2" || local put_result=$?
    if [ "$put_result" -ne 0 ]; then
      echo "error adding object"
      return 1
    fi
  fi
  return 0
}

# delete object from versitygw
# param:  object path, including bucket name
# return 0 for success, 1 for failure
delete_object() {
  if [ $# -ne 2 ]; then
    echo "delete object command requires command type, object parameter"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3 rm s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 's3cmd' ]]; then
    error=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate rm s3://"$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure rm "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error deleting object: $error"
    return 1
  fi
  return 0
}

# list buckets on versitygw
# params:  format (aws, s3cmd)
# export bucket_array (bucket names) on success, return 1 for failure
list_buckets() {
  if [[ $# -ne 1 ]]; then
    echo "List buckets command missing format"
    return 1
  fi

  local exit_code=0
  local output
  if [[ $1 == "aws" ]]; then
    output=$(aws --no-verify-ssl s3 ls s3:// 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    output=$(s3cmd "${S3CMD_OPTS[@]}" --no-check-certificate ls s3:// 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    output=$(mc --insecure ls "$MC_ALIAS" 2>&1) || exit_code=$?
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

# list objects on versitygw, in bucket or folder
# param:  path of bucket or folder
# export object_array (object names) on success, return 1 for failure
list_objects() {
  if [ $# -ne 2 ]; then
    echo "list objects command requires command type, and bucket or folder"
    return 1
  fi
  local exit_code=0
  local output
  if [[ $1 == "aws" ]]; then
    output=$(aws --no-verify-ssl s3 ls s3://"$2" 2>&1) || exit_code=$?
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

  object_array=()
  while IFS= read -r line; do
    if [[ $line != *InsecureRequestWarning* ]]; then
      object_name=$(echo "$line" | awk '{print $NF}')
      object_array+=("$object_name")
    fi
  done <<< "$output"

  export object_array
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

# get bucket acl
# param:  bucket path
# export acl for success, return 1 for error
get_bucket_acl() {
  if [ $# -ne 1 ]; then
    echo "bucket ACL command missing bucket name"
    return 1
  fi
  local exit_code=0
  acl=$(aws --no-verify-ssl s3api get-bucket-acl --bucket "$1" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "Error getting bucket ACLs: $acl"
    return 1
  fi
  export acl
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
    echo "invalid command type $1"
    return 1
  fi
  if [[ $result -ne 0 ]]; then
    echo "Error adding bucket tag: $error"
    return 1
  fi
  return 0
}

# get bucket tags
# params:  bucket
# export 'tags' on success, return 1 for error
get_bucket_tags() {
  if [ $# -ne 2 ]; then
    echo "get bucket tag command missing command type, bucket name"
    return 1
  fi
  local result
  if [[ $1 == 'aws' ]]; then
    tags=$(aws --no-verify-ssl s3api get-bucket-tagging --bucket "$2" 2>&1) || result=$?
  elif [[ $1 == 'mc' ]]; then
    tags=$(mc --insecure tag list "$MC_ALIAS"/"$2" 2>&1) || result=$?
  else
    echo "invalid command type $1"
    return 1
  fi
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
    echo "error getting object tags: $tags"
    return 1
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

# run the abort multipart command
# params:  bucket, key, upload ID
# return 0 for success, 1 for failure
run_abort_command() {
  if [ $# -ne 3 ]; then
    echo "command to run abort requires bucket, key, upload ID"
    return 1
  fi

  error=$(aws --no-verify-ssl s3api abort-multipart-upload --bucket "$1" --key "$2" --upload-id "$3") || local aborted=$?
  if [[ $aborted -ne 0 ]]; then
    echo "Error aborting upload: $error"
    return 1
  fi
  return 0
}

# run upload, then abort it
# params:  bucket, key, local file location, number of parts to split into before uploading
# return 0 for success, 1 for failure
abort_multipart_upload() {
  if [ $# -ne 4 ]; then
    echo "abort multipart upload command missing bucket, key, file, and/or part count"
    return 1
  fi

  multipart_upload_before_completion "$1" "$2" "$3" "$4" || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error performing pre-completion multipart upload"
    return 1
  fi

  run_abort_command "$1" "$2" "$upload_id"
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
    put_object "aws" "$3"-"$i" "$1" || put_result=$?
    if [[ $put_result -ne 0 ]]; then
      echo "error putting object"
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

head_bucket() {
  if [ $# -ne 2 ]; then
    echo "head bucket command missing command type, bucket name"
    return 1
  fi
  local exit_code=0
  local error
  if [[ $1 == "aws" ]]; then
    bucket_info=$(aws --no-verify-ssl s3api head-bucket --bucket "$2" 2>&1) || exit_code=$?
  elif [[ $1 == "s3cmd" ]]; then
    bucket_info=$(s3cmd --no-check-certificate info "s3://$2" 2>&1) || exit_code=$?
  elif [[ $1 == 'mc' ]]; then
    bucket_info=$(mc --insecure stat "$MC_ALIAS"/"$2" 2>&1) || exit_code=$?
  else
    echo "invalid command type $1"
    return 1
  fi
  if [ $exit_code -ne 0 ]; then
    echo "error getting bucket info: $bucket_info"
    return 1
  fi
  export bucket_info
}
