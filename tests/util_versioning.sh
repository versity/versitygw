#!/usr/bin/env bash

source ./tests/commands/get_bucket_versioning.sh
source ./tests/commands/list_object_versions.sh

check_if_versioning_enabled() {
  if [ $# -ne 1 ]; then
    log 2 "'check_if_versioning_enabled' requires bucket name"
    return 2
  fi
  if ! get_bucket_versioning 's3api' "$1"; then
    log 2 "error getting bucket versioning"
    return 2
  fi
  # shellcheck disable=SC2154
  if ! status=$(echo "$versioning" | grep -v "InsecureRequestWarning" | jq -r ".Status" 2>&1); then
    log 2 "error parsing 'Status' value: $status"
    return 2
  fi
  if [[ "$status" == "Enabled" ]]; then
    return 0
  fi
  return 1
}

delete_old_versions() {
  if [ $# -ne 1 ]; then
    log 2 "'delete_old_versions' requires bucket name"
    return 1
  fi
  if ! list_object_versions "$1"; then
    log 2 "error listing object versions"
    return 1
  fi
  # shellcheck disable=SC2154
  log 5 "versions: $versions"
  version_keys=()
  version_ids=()

  if ! parse_version_data "$versions" '.Versions[]'; then
    log 2 "error parsing Versions elements"
    return 1
  fi
  if ! parse_version_data "$versions" '.DeleteMarkers[]'; then
    log 2 "error getting DeleteMarkers elements"
    return 1
  fi

  log 5 "version keys: ${version_keys[*]}"
  log 5 "version IDs: ${version_ids[*]}"
  for idx in "${!version_keys[@]}"; do
    log 5 "idx: $idx"
    log 5 "version ID: ${version_ids[$idx]}"
    # shellcheck disable=SC2154
    if [ "$lock_config_exists" == "true" ]; then
      if ! delete_object_version_bypass_retention "$1" "${version_keys[$idx]}" "${version_ids[$idx]}"; then
        log 2 "error deleting object version"
        return 1
      fi
    else
      if ! delete_object_version "$1" "${version_keys[$idx]}" "${version_ids[$idx]}"; then
        log 2 "error deleting object version"
        return 1
      fi
    fi
  done
}

parse_version_data() {
  if [ $# -ne 2 ]; then
    log 2 "'parse_version_data' requires raw data, element name"
    return 1
  fi
  if ! version_data="$(echo "$1" | jq -c "$2" 2>&1)"; then
    if [[ "$version_data" == *"Cannot iterate over null"* ]]; then
      return 0
    fi
  fi
  log 5 "version data: ${version_data[*]}"
  # shellcheck disable=SC2048
  for version in ${version_data[*]}; do
    if ! key=$(echo "$version" | jq -r '.Key' 2>&1); then
      log 2 "error getting version key: $key (version: $version)"
      return 1
    fi
    version_keys+=("$key")
    if ! version_id=$(echo "$version" | jq -r '.VersionId' 2>&1); then
      log 2 "error getting version id: $version_id (version: $version)"
      return 1
    fi
    version_ids+=("$version_id")
  done
}

check_versioning_status_rest() {
  if [ $# -ne 2 ]; then
    log 2 "'check_versioning_status_rest' requires bucket, expected value"
    return 1
  fi
  if ! get_bucket_versioning_rest "$BUCKET_ONE_NAME"; then
    log 2 "error getting bucket versioning"
    return 1
  fi
  log 5 "versioning: $(cat "$TEST_FILE_FOLDER/versioning.txt")"
  if ! versioning_info=$(xmllint --xpath '//*[local-name()="VersioningConfiguration"]' "$TEST_FILE_FOLDER/versioning.txt" 2>&1); then
    log 2 "error getting VersioningConfiguration value: $versioning_info"
    return 1
  fi
  versioning_status=""
  if ! has_status=$(echo "$versioning_info" | xmllint --xpath 'boolean(//*[local-name()="Status"]/text())' - 2>&1); then
    log 2 "error getting if versioning status: $has_status"
    return 1
  fi
  if [ "$has_status" == true ]; then
    if ! versioning_status=$(echo "$versioning_info" | xmllint --xpath '//*[local-name()="Status"]/text()' - 2>&1); then
      log 2 "error getting versioning status: $versioning_status"
      return 1
    fi
  fi
  if [ "$versioning_status" != "$2" ]; then
    log 2 "versioning info should be '$2', is $versioning_status"
    return 1
  fi
  return 0
}

get_and_check_versions_rest() {
  if [ $# -lt 5 ]; then
    log 2 "'get_and_check_versionid_null_rest' requires bucket, key, count, expected islatest, expected id equal to null"
    return 1
  fi
  if ! list_object_versions_rest "$1"; then
    log 2 "error listing object versions"
    return 1
  fi
  log 5 "versions: $(cat "$TEST_FILE_FOLDER/object_versions.txt")"
  if ! version_count=$(xmllint --xpath 'count(//*[local-name()="Version"])' "$TEST_FILE_FOLDER/object_versions.txt" 2>&1); then
    log 2 "error getting version count: $version_count"
    return 1
  fi
  log 5 "version count: $version_count"
  if [ "$version_count" != "$3" ]; then
    log 2 "version count mismatch (expected 1, actual $version_count)"
    return 1
  fi
  while [ $# -ge 5 ]; do
    if [ "$5" == "true" ]; then
      id_check="="
    else
      id_check="!="
    fi
    match_string="//*[local-name()=\"Version\"][*[local-name()=\"VersionId\" and text()$id_check\"null\"] and *[local-name()=\"IsLatest\" and text()=\"$4\"]]"
    log 5 "match string: $match_string"
    if ! xmllint --xpath "$match_string" "$TEST_FILE_FOLDER/object_versions.txt" 2>&1; then
      return 1
    fi
    shift 2
  done
  return 0
}
