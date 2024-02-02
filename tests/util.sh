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

# create bucket if it doesn't exist
# param:  bucket name
# return 0 for success, 1 for failure
check_and_create_bucket() {
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
  local create_result
  if [[ $exists_result -eq 1 ]]; then
    create_bucket "$1" || create_result=$?
    if [[ $create_result -ne 0 ]]; then
      echo "Error creating bucket"
      return 1
    fi
  fi
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
  if [ $exists_result -eq 2 ]; then
    echo "error checking if object exists"
    return 1
  fi
  if [ $exists_result -eq 1 ]; then
    put_object "$1" "$2" || local put_result=$?
    if [ $put_result -ne 0 ]; then
      echo "error adding object"
      return 1
    fi
  fi
  return 0
}

# delete object from versitygw
# param:  object location
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
    echo "Error: $acl"
    return 1
  fi
  export acl
}
