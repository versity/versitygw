#!/usr/bin/env bats

# create an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
create_bucket() {
  if [ $# -ne 1 ]; then
    echo "create bucket missing bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 mb s3://"$1" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error creating bucket: $error"
    return 1
  fi
  return 0
}

# delete an AWS bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket() {
  if [ $# -ne 1 ]; then
    echo "delete bucket missing bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 rb s3://"$1" 2>&1) || exit_code="$?"
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
  if [ $# -ne 1 ]; then
    echo "delete bucket missing bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 rb s3://"$1" --force 2>&1) || exit_code="$?"
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

# delete contents of a bucket
# param:  bucket name
# return 0 for success, 1 for failure
delete_bucket_contents() {
  if [ $# -ne 1 ]; then
    echo "delete bucket missing bucket name"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 rm s3://"$1" --recursive 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "error deleting bucket: $error"
    return 1
  fi
  return 0
}

# check if bucket exists
# param:  bucket name
# return 0 for true, 1 for false, 2 for error
bucket_exists() {
  if [ $# -ne 1 ]; then
    echo "bucket exists check missing bucket name"
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws s3 ls s3://"$1" 2>&1) || exit_code="$?"
  echo "Exit code: $exit_code, error: $error"
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == *"The specified bucket does not exist"* ]] || [[ "$error" == *"Access Denied"* ]]; then
      return 1
    else
      echo "error checking if bucket exists: $error"
      return 2
    fi
  fi
  return 0
}

# delete buckets or just the contents depending on RECREATE_BUCKETS parameter
# param:  bucket name
# return:  0 for success, 1 for failure
delete_bucket_or_contents() {
  if [ $# -ne 1 ]; then
    echo "delete bucket or contents function requires bucket name"
    return 1
  fi
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    delete_bucket_contents "$1" || local delete_result=$?
    if [[ $delete_result -ne 0 ]]; then
      echo "error deleting bucket contents"
      return 1
    fi
    return 0
  fi
  delete_bucket_recursive "$1" || local delete_result=$?
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
  if [ $# -ne 1 ]; then
    echo "bucket creation function requires bucket name"
    return 1
  fi
  local exists_result
  bucket_exists "$1" || exists_result=$?
  if [[ $exists_result -eq 2 ]]; then
    echo "Bucket existence check error"
    return 1
  fi
  if [[ $exists_result -eq 0 ]]; then
    delete_bucket_or_contents "$1" || delete_result=$?
    if [[ delete_result -ne 0 ]]; then
      echo "error deleting bucket or contents"
      return 1
    fi
  fi
  if [[ $RECREATE_BUCKETS != "true" ]]; then
    echo "When RECREATE_BUCKETS isn't set to \"true\", buckets should be pre-created by user"
    return 1
  fi
  local create_result
  create_bucket "$1" || create_result=$?
  if [[ $create_result -ne 0 ]]; then
    echo "Error creating bucket"
    return 1
  fi
  echo "Bucket creation success"
  return 0
}

# check if object exists on S3 via gateway
# param:  object path
# return 0 for true, 1 for false, 2 for error
object_exists() {
  if [ $# -ne 1 ]; then
    echo "object exists check missing object name"
    return 2
  fi
  local exit_code=0
  local error
  error=$(aws s3 ls s3://"$1" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    if [[ "$error" == "" ]]; then
      return 1
    else
      echo "error checking if object exists: $error"
      return 2
    fi
  fi
  return 0
}

# add object to versitygw
# params:  source file, destination copy location
# return 0 for success, 1 for failure
put_object() {
  if [ $# -ne 2 ]; then
    echo "put object command requires source, destination"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 cp "$1" s3://"$2" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error copying object to bucket: $error"
    return 1
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
  object_exists "$2" || local exists_result=$?
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
  if [ $# -ne 1 ]; then
    echo "delete object command requires object parameter"
    return 1
  fi
  local exit_code=0
  local error
  error=$(aws s3 rm s3://"$1" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error deleting object: $error"
    return 1
  fi
  return 0
}

# list buckets on versitygw
# no params
# export bucket_array (bucket names) on success, return 1 for failure
list_buckets() {
  local exit_code=0
  local output
  output=$(aws s3 ls 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error listing buckets: $output"
    return 1
  fi

  bucket_array=()
  while IFS= read -r line; do
    bucket_name=$(echo "$line" | awk '{print $NF}')
    bucket_array+=("$bucket_name")
  done <<< "$output"

  export bucket_array
}

# list objects on versitygw, in bucket or folder
# param:  path of bucket or folder
# export object_array (object names) on success, return 1 for failure
list_objects() {
  if [ $# -ne 1 ]; then
    echo "list objects command requires bucket or folder"
    return 1
  fi
  local exit_code=0
  local output
  output=$(aws s3 ls s3://"$1" 2>&1) || exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "error listing objects: $output"
    return 1
  fi

  object_array=()
  while IFS= read -r line; do
    object_name=$(echo "$line" | awk '{print $NF}')
    object_array+=("$object_name")
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
  error=$(aws s3api head-bucket --bucket "$1" 2>&1) || exit_code="$?"
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
  object_data=$(aws s3api head-object --bucket "$1" --key "$2" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "Error obtaining object data: $object_data"
    return 2
  fi
  etag=$(echo "$object_data" | jq '.ETag')
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
  acl=$(aws s3api get-bucket-acl --bucket "$1" 2>&1) || exit_code="$?"
  if [ $exit_code -ne 0 ]; then
    echo "Error getting bucket ACLs: $acl"
    return 1
  fi
  export acl
}

# add tags to bucket
# params:  bucket, key, value
# return:  0 for success, 1 for error
put_bucket_tag() {
  if [ $# -ne 3 ]; then
    echo "bucket tag command missing bucket name, key, value"
    return 1
  fi
  local error
  local result
  error=$(aws s3api put-bucket-tagging --bucket "$1" --tagging "TagSet=[{Key=$2,Value=$3}]") || result=$?
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
  if [ $# -ne 1 ]; then
    echo "get bucket tag command missing bucket name"
    return 1
  fi
  local result
  tags=$(aws s3api get-bucket-tagging --bucket "$1") || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error getting bucket tags: $tags"
    return 1
  fi
  export tags
}

# add tags to object
# params:  object, key, value
# return:  0 for success, 1 for error
put_object_tag() {
  if [ $# -ne 4 ]; then
    echo "object tag command missing object name, file, key, and/or value"
    return 1
  fi
  local error
  local result
  error=$(aws s3api put-object-tagging --bucket "$1" --key "$2" --tagging "TagSet=[{Key=$3,Value=$4}]") || result=$?
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
  if [ $# -ne 2 ]; then
    echo "get object tag command missing bucket and/or key"
    return 1
  fi
  local result
  tags=$(aws s3api get-object-tagging --bucket "$1" --key "$2") || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error getting object tags: $tags"
    return 1
  fi
  export tags
}

# create a test file and export folder.  do so in temp folder
# params:  filename
# export test file folder on success, return 1 for error
create_test_files() {
  if [ $# -lt 1 ]; then
    echo "create test files command missing filename"
    return 1
  fi
  test_file_folder=.
  if [[ -z "$GITHUB_ACTIONS" ]]; then
    test_file_folder=${TMPDIR}versity-gwtest
    mkdir -p "$test_file_folder" || local mkdir_result=$?
    if [[ $mkdir_result -ne 0 ]]; then
      echo "error creating test file folder"
    fi
  fi
  for name in "$@"; do
    touch "$test_file_folder"/"$name" || local touch_result=$?
    if [[ $touch_result -ne 0 ]]; then
      echo "error creating file $name"
    fi
  done
  export test_file_folder
}

# delete a test file
# params:  filename
# return:  0 for success, 1 for error
delete_test_files() {
  if [ $# -lt 1 ]; then
    echo "delete test files command missing filenames"
    return 1
  fi
  if [ -z "$test_file_folder" ]; then
    echo "no test file folder defined, not deleting"
    return 1
  fi
  for name in "$@"; do
    rm "$test_file_folder"/"$name" || rm_result=$?
    if [[ $rm_result -ne 0 ]]; then
      echo "error deleting file $name"
    fi
  done
  return 0
}

# list objects in bucket, v1
# param:  bucket
# export objects on success, return 1 for failure
list_objects_s3api_v1() {
  if [ $# -ne 1 ]; then
    echo "list objects command missing bucket"
    return 1
  fi
  objects=$(aws s3api list-objects --bucket "$1") || local result=$?
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
  objects=$(aws s3api list-objects-v2 --bucket "$1") || local result=$?
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
  multipart_data=$(aws s3api create-multipart-upload --bucket "$1" --key "$2") || local created=$?
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
  etag_json=$(aws s3api upload-part --bucket "$1" --key "$2" --upload-id "$3" --part-number "$5" --body "$4-$(($5-1))") || local uploaded=$?
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

  file_size=$(stat -c %s "$3" 2>/dev/null || stat -f %z "$3" 2>/dev/null)
  part_size=$((file_size / $4))
  remainder=$((file_size % $4))
  if [[ remainder -ne 0 ]]; then
    part_size=$((part_size+1))
  fi
  local error
  local split_result
  error=$(split -a 1 -d -b "$part_size" "$3" "$3"-) || split_result=$?
  if [[ $split_result -ne 0 ]]; then
    echo "error splitting file: $error"
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

  error=$(aws s3api complete-multipart-upload --bucket "$1" --key "$2" --upload-id "$upload_id" --multipart-upload '{"Parts": '"$parts"'}') || local completed=$?
  if [[ $completed -ne 0 ]]; then
    echo "Error completing upload: $error"
    return 1
  fi
  return 0
}

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

  error=$(aws s3api abort-multipart-upload --bucket "$1" --key "$2" --upload-id "$upload_id") || local aborted=$?
  if [[ $aborted -ne 0 ]]; then
    echo "Error aborting upload: $error"
    return 1
  fi
  return 0
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
  error=$(aws s3 cp "$1" "$2") || result=$?
  if [[ $result -ne 0 ]]; then
    echo "error copying file: $error"
    return 1
  fi
  return 0
}
