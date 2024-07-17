#!/usr/bin/env bash

# list objects in bucket, v2
# param:  bucket
# export objects on success, return 1 for failure
list_objects_v2() {
  if [ $# -ne 1 ]; then
    echo "list objects command missing bucket and/or path"
    return 1
  fi
  record_command "list-objects-v2 client:s3api"
  objects=$(aws --no-verify-ssl s3api list-objects-v2 --bucket "$1") || local result=$?
  if [[ $result -ne 0 ]]; then
    echo "error listing objects: $objects"
    return 1
  fi
  export objects
}