#!/usr/bin/env bash

select_object_content() {
  if [[ $# -ne 7 ]]; then
    log 2 "'select object content' command requires bucket, key, expression, expression type, input serialization, output serialization, outfile"
    return 1
  fi
  error=$(aws --no-verify-ssl s3api select-object-content \
    --bucket "$1" \
    --key "$2" \
    --expression "$3" \
    --expression-type "$4" \
    --input-serialization "$5" \
    --output-serialization "$6" "$7" 2>&1) || local select_result=$?
  if [[ $select_result -ne 0 ]]; then
    log 2 "error selecting object content: $error"
    return 1
  fi
  return 0
}