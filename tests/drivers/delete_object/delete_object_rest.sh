#!/usr/bin/env bash

# Copyright 2024 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

source ./tests/commands/list_objects_v2.sh
source ./tests/drivers/list_object_versions/list_object_versions_rest.sh
source ./tests/drivers/xml.sh
source ./tests/drivers/get_object_legal_hold/get_object_legal_hold_rest.sh

list_and_delete_objects() {
  if ! check_param_count_v2 "bucket, lock config exists" 2 $#; then
    return 1
  fi
  local bucket="$1" lock_config_exists="$2"

  local response
  if ! response=$(list_objects_rest_go "$bucket" "parse_objects_list_rest" 2>&1); then
    log 2 "error getting object list: $response"
    return 1
  fi
  mapfile -t object_array <<< "$response"
  log 5 "objects: ${object_array[*]}"
  for object in "${object_array[@]}"; do
    if [ "$object" == "" ]; then
      break
    fi
    if ! clear_object_in_bucket "$bucket" "$object"; then
      log 2 "error deleting object $object"
      return 1
    fi
  done

  if ! delete_old_versions "$bucket" "$lock_config_exists"; then
    log 2 "error deleting old version"
    return 1
  fi
  return 0
}

delete_old_versions() {
  if ! check_param_count_v2 "bucket, lock config exists (true or false)" 2 $#; then
    return 1
  fi
  local bucket="$1" lock_config_exists="$2"
  local response versions_xml

  if ! response=$(list_object_versions_rest_v2 "$bucket" "get_xml_versions_data" 2>&1); then
    log 2 "error listing object versions: $response"
    return 1
  fi
  versions_xml="$response"

  if ! response=$(get_and_delete_old_versions_from_xml "$versions_xml" "Version" "$bucket" "$lock_config_exists" 2>&1); then
    log 2 "error deleting Versions: $response"
    return 1
  fi
  if ! response=$(get_and_delete_old_versions_from_xml "$versions_xml" "DeleteMarker" "$bucket" "$lock_config_exists" 2>&1); then
    log 2 "error deleting DeleteMarkers: $response"
    return 1
  fi
  return 0
}

get_and_delete_old_versions_from_xml() {
  if ! check_param_count_v2 "version XML, 'Version' or 'DeleteMarker', bucket, lock config exists" $# 4; then
    return 1
  fi
  local version_xml="$1" version_or_delete_marker="$2" bucket="$3" lock_config_exists="$4"

  while IFS= read -r key && IFS= read -r version_id; do
    if ! delete_single_version_or_delete_marker "$bucket" "$lock_config_exists" "$key" "$version_id"; then
      log 2 "error deleting key '$key', version ID '$version_id'"
      return 1
    fi
  done < <(xmlstarlet sel -t \
               -m '//*[local-name()='"\"$version_or_delete_marker\""']' \
               -v '*[local-name()="Key"]' -n \
               -v '*[local-name()="VersionId"]' -n \
               <<<"$version_xml" | xmlstarlet unesc)
  return 0
}

delete_single_version_or_delete_marker() {
  if ! check_param_count_v2 "bucket, lock config exists, key, version ID" 4 $#; then
    return 1
  fi
  local bucket="$1" lock_config="$2" key="$3" version_id="$4"

  if [ "$lock_config" == "true" ]; then
    if ! check_remove_legal_hold_versions "$bucket" "$key" "$version_id"; then
      log 2 "error checking, removing legal hold versions"
      return 1
    fi
    if ! delete_object_version_rest_bypass_retention "$bucket" "$key" "$version_id"; then
      log 2 "error deleting object version, bypassing retention"
      return 1
    fi
  else
    if ! delete_object_version_rest "$bucket" "$key" "$version_id"; then
      log 2 "error deleting object version"
      return 1
    fi
  fi
  log 5 "successfully deleted version with key '$key', id '$version_id'"
  return 0
}

delete_object_version_with_or_without_retention_base64() {
  if ! check_param_count_v2 "bucket, key/value pair" 2 $#; then
    return 1
  fi
  IFS=":" read -ra key_and_id <<< "$2"
  log 5 "key and ID: ${key_and_id[*]}"
  if ! key=$(printf '%s' "${key_and_id[0]}" | base64 --decode 2>&1); then
    log 2 "error decoding key: $key"
    return 1
  fi
  if ! id=$(printf '%s' "${key_and_id[1]}" | base64 --decode 2>&1); then
    log 2 "error decoding ID: $id"
    return 1
  fi
  # shellcheck disable=SC2154
  if [ "$lock_config_exists" == "true" ]; then
    if ! check_remove_legal_hold_versions "$1" "$key" "$id"; then
      log 2 "error checking, removing legal hold versions"
      return 1
    fi
    if ! delete_object_version_rest_bypass_retention "$1" "$key" "$id"; then
      log 2 "error deleting object version, bypassing retention"
      return 1
    fi
  else
    if ! delete_object_version_rest "$1" "$key" "$id"; then
      log 2 "error deleting object version"
      return 1
    fi
  fi
  log 5 "successfully deleted version with key '$key', id '$id'"
  return 0
}

put_object_with_lock_mode_and_delete_latest_version() {
  if ! check_param_count_v2 "file, bucket, key, later time" 4 $#; then
    return 1
  fi
  if ! send_rest_go_command "200" \
    "-bucketName" "$2" "-objectKey" "$3" "-payloadFile" "$1" \
    "-method" "PUT" "-contentMD5" "-signedParams" "x-amz-object-lock-mode:GOVERNANCE,x-amz-object-lock-retain-until-date:$4"; then
      log 2 "error sending put object command with object lock"
      return 1
  fi

  local response
  if ! response=$(send_rest_go_command_callback "200" "parse_latest_version_id" \
      "-method" "GET" "-bucketName" "$2" "-query" "versions=" 2>&1); then
    log 2 "error checking versions before deletion: $response"
    return 1
  else
    version_id="$response"
  fi
  log 5 "version ID: $version_id"
  if ! delete_object_version_rest_expect_error "$2" "$3" "$version_id" "403" "AccessDenied" "object protected by object lock"; then
    log 2 "shouldn't have been able to delete"
    return 1
  fi
  sleep 15
  if ! delete_object_version "$2" "$3" "$version_id"; then
    log 2 "error deleting object version"
    return 1
  fi
  return 0
}

attempt_to_delete_version_after_retention_policy() {
  if ! check_param_count_v2 "file, bucket name, key" 3 $#; then
    return 1
  fi
  if ! send_rest_go_command "200" \
    "-bucketName" "$2" "-objectKey" "$3" "-payloadFile" "$1" "-method" "PUT" "-contentMD5"; then
      log 2 "error sending put object command"
      return 1
  fi

  local response
  if ! response=$(send_rest_go_command_callback "200" "parse_latest_version_id" \
      "-method" "GET" "-bucketName" "$2" "-query" "versions=" 2>&1); then
    log 2 "error checking versions before deletion: $response"
    return 1
  fi

  version_id="$response"
  if ! delete_object_version_rest_expect_error "$2" "$3" "$version_id" "403" "AccessDenied" "object protected by object lock"; then
    log 2 "shouldn't have been able to delete"
    return 1
  fi
}

delete_delete_marker() {
  if ! check_param_count_v2 "data file" 1 $#; then
    return 1
  fi
  if ! parse_version_or_delete_marker_id "$1" "DeleteMarker" "true"; then
    echo "error parsing delete marker ID"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "version or marker ID: $version_or_marker_id"
  if ! delete_object_version_rest "$bucket_name" "$object_key" "$version_or_marker_id"; then
    log 2 "error deleting delete marker"
    return 1
  fi
}

delete_delete_marker_without_object_lock() {
  if ! check_param_count_v2 "bucket name, key" 2 $#; then
    return 1
  fi
  bucket_name="$1"
  object_key="$2"
  if ! list_object_versions_rest_v2 "$bucket_name" "delete_delete_marker"; then
    return 1
  fi
  return 0
}
