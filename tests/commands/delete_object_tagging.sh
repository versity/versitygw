#!/usr/bin/env bash

delete_object_tagging() {
  if [[ $# -ne 3 ]]; then
    echo "delete object tagging command missing command type, bucket, key"
    return 1
  fi
  if [[ $1 == 'aws' ]]; then
    error=$(aws --no-verify-ssl s3api delete-object-tagging --bucket "$2" --key "$3" 2>&1) || delete_result=$?
  elif [[ $1 == 'mc' ]]; then
    error=$(mc --insecure tag remove "$MC_ALIAS/$2/$3") || delete_result=$?
  else
    echo "delete-object-tagging command not implemented for '$1'"
    return 1
  fi
  if [[ $delete_result -ne 0 ]]; then
    echo "error deleting object tagging: $error"
    return 1
  fi
  return 0
}