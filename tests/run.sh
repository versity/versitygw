#!/bin/bash

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

# Function to display help information
show_help() {
    echo "Usage: $0 [option...]"
    echo "   -h, --help                             Display this help message and exit"
    echo "                                          Separate the below by comma"
    echo "   s3api                                  Run all tests with s3api cli"
    echo "   s3api-multipart                        Run multipart tests with s3api cli"
    echo "   s3api-bucket                           Run bucket tests with s3api cli"
    echo "   s3api-object                           Run object tests with s3api cli"
    echo "   s3api-policy                           Run policy tests with s3api cli"
    echo "   s3api-user                             Run user tests with s3api cli"
    echo "   s3                                     Run tests with s3 cli"
    echo "   s3cmd                                  Run tests with s3cmd utility"
    echo "   s3cmd-user                             Run user tests with s3cmd utility"
    echo "   s3cmd-non-user                         Run non-user tests with s3cmd utility"
    echo "   s3cmd-file-count                       Run file count test with s3cmd utility"
    echo "   mc                                     Run tests with mc utility"
    echo "   mc-non-file-count                      Run non-file count tests with mc utility"
    echo "   mc-file-count                          Run file count test with mc utility"
    echo "   rest                                   Run tests with rest cli"
    echo "   rest-base                              Run REST base tests"
    echo "   rest-acl                               Run REST ACL tests"
    echo "   rest-chunked                           Run REST chunked upload tests"
    echo "   rest-checksum                          Run REST checksum tests"
    echo "   rest-create-bucket                     Run REST create bucket tests"
    echo "   rest-delete-bucket-ownership-controls  Run REST delete bucket ownership controls tests"
    echo "   rest-delete-bucket-tagging             Run REST delete bucket tagging tests"
    echo "   rest-get-bucket-location               Run REST get bucket location tests"
    echo "   rest-get-object-tagging                Run REST get object tagging tests"
    echo "   rest-head-bucket                       Run REST head bucket tests"
    echo "   rest-list-buckets                      Run REST list-buckets tests"
    echo "   rest-list-object-versions              Run REST list-object-versions tests"
    echo "   rest-multipart                         Run REST multipart tests"
    echo "   rest-not-implemented                   Run REST multipart tests"
    echo "   rest-put-bucket-tagging                Run REST put-bucket-tagging tests"
    echo "   rest-put-object                        Run REST put-object tests"
    echo "   rest-put-object-tagging                Run REST put-object-tagging tests"
    echo "   rest-versioning                        Run REST versioning tests"
    echo "   rest-bucket                            Run REST bucket tests"
}

handle_param() {
  case $1 in
      -h|--help)
          show_help
          exit 0
          ;;
      s3|s3-file-count|s3-non-file-count|s3api|s3cmd|s3cmd-user|s3cmd-non-user|\
      s3cmd-file-count|mc|mc-non-file-count|mc-file-count|s3api-user|rest|s3api-policy|\
      s3api-bucket|s3api-object|s3api-multipart|rest-base|rest-acl|rest-chunked|rest-checksum|\
      rest-create-bucket|rest-head-bucket|rest-list-buckets|rest-not-implemented|\
      rest-put-object|rest-versioning|rest-bucket|rest-multipart|rest-delete-bucket-ownership-controls|\
      rest-delete-bucket-tagging|setup-remove-static|rest-put-bucket-tagging|rest-get-bucket-location|\
      rest-put-object-tagging|rest-get-object-tagging|rest-list-object-versions|rest-get-bucket-policy-status)
          run_suite "$1"
          ;;
      *) # Handle unrecognized options or positional arguments
          echo "Unrecognized option: $1" >&2
          exit 1
          ;;
  esac
}

run_suite() {
  exit_code=0
  case $1 in
    s3api)
      echo "Running all s3api tests ..."
      "$HOME"/bin/bats ./tests/test_s3api_bucket.sh || exit_code=$?
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_s3api_object.sh || exit_code=$?
      fi
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_s3api_policy.sh || exit_code=$?
      fi
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_s3api_multipart.sh || exit_code=$?
      fi
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_user_aws.sh || exit_code=$?
      fi
      ;;
    s3api-multipart)
      echo "Running s3api multipart tests ..."
      "$HOME"/bin/bats ./tests/test_s3api_multipart.sh || exit_code=$?
      ;;
    s3api-policy)
      echo "Running s3api policy tests ..."
      "$HOME"/bin/bats ./tests/test_s3api_policy.sh || exit_code=$?
      ;;
    s3api-bucket)
      echo "Running s3api bucket tests ..."
      "$HOME"/bin/bats ./tests/test_s3api_bucket.sh || exit_code=$?
      ;;
    s3api-object)
      echo "Running s3api object tests ..."
      "$HOME"/bin/bats ./tests/test_s3api_object.sh || exit_code=$?
      ;;
    s3)
      echo "Running s3 tests ..."
      "$HOME"/bin/bats ./tests/test_s3.sh || exit_code=$?
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_s3_file_count.sh || exit_code=$?
      fi
      ;;
    s3-non-file-count)
      echo "Running s3 non-file count tests ..."
      "$HOME"/bin/bats ./tests/test_s3.sh || exit_code=$?
      ;;
    s3-file-count)
      echo "Running s3 file count test ..."
      "$HOME"/bin/bats ./tests/test_s3_file_count.sh || exit_code=$?
      ;;
    s3cmd)
      echo "Running s3cmd tests ..."
      "$HOME"/bin/bats ./tests/test_s3cmd.sh || exit_code=$?
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_user_s3cmd.sh || exit_code=$?
      fi
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_s3cmd_file_count.sh || exit_code=$?
      fi
      ;;
    s3cmd-user)
      echo "Running s3cmd user tests ..."
      "$HOME"/bin/bats ./tests/test_user_s3cmd.sh || exit_code=$?
      ;;
    s3cmd-non-user)
      echo "Running s3cmd non-user tests ..."
      "$HOME"/bin/bats ./tests/test_s3cmd.sh || exit_code=$?
      ;;
    s3cmd-file-count)
      echo "Running s3cmd file count test ..."
      "$HOME"/bin/bats ./tests/test_s3cmd_file_count.sh || exit_code=$?
      ;;
    mc)
      echo "Running mc tests ..."
      "$HOME"/bin/bats ./tests/test_mc.sh || exit_code=$?
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_mc_file_count.sh || exit_code=$?
      fi
      ;;
    mc-non-file-count)
      echo "Running mc non-file count tests ..."
      "$HOME"/bin/bats ./tests/test_mc.sh || exit_code=$?
      ;;
    mc-file-count)
      echo "Running mc file count test ..."
      "$HOME"/bin/bats ./tests/test_mc_file_count.sh || exit_code=$?
      ;;
    rest)
      echo "Running rest tests ..."
      if ! "$HOME"/bin/bats ./tests/test_rest.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_acl.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_chunked.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_checksum.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_create_bucket.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_delete_bucket_ownership_controls.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_get_bucket_location.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_get_bucket_policy_status.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_get_object_tagging.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_head_bucket.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_list_buckets.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_list_object_versions.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_multipart.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_not_implemented.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_put_bucket_tagging.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_put_object.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_put_object_tagging.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_versioning.sh; then
        exit_code=1
      elif ! "$HOME"/bin/bats ./tests/test_rest_bucket.sh; then
        exit_code=1
      fi
      ;;
    rest-base)
      echo "Running REST base tests ..."
      "$HOME"/bin/bats ./tests/test_rest.sh || exit_code=$?
      ;;
    rest-acl)
      echo "Running REST ACL tests ..."
      "$HOME"/bin/bats ./tests/test_rest_acl.sh || exit_code=$?
      ;;
    rest-bucket)
      echo "Running REST bucket tests ..."
      "$HOME"/bin/bats ./tests/test_rest_bucket.sh || exit_code=$?
      ;;
    rest-chunked)
      echo "Running REST chunked upload tests ..."
      "$HOME"/bin/bats ./tests/test_rest_chunked.sh || exit_code=$?
      ;;
    rest-checksum)
      echo "Running REST checksum tests ..."
      "$HOME"/bin/bats ./tests/test_rest_checksum.sh || exit_code=$?
      ;;
    rest-create-bucket)
      echo "Running REST create bucket tests ..."
      "$HOME"/bin/bats ./tests/test_rest_create_bucket.sh || exit_code=$?
      ;;
    rest-delete-bucket-ownership-controls)
      echo "Running REST delete bucket ownership controls tests ..."
      "$HOME"/bin/bats ./tests/test_rest_delete_bucket_ownership_controls.sh || exit_code=$?
      ;;
    rest-delete-bucket-tagging)
      echo "Running REST delete bucket tagging tests ..."
      "$HOME"/bin/bats ./tests/test_rest_delete_bucket_tagging.sh || exit_code=$?
      ;;
    rest-get-bucket-location)
      echo "Running REST get bucket location tests ..."
      "$HOME"/bin/bats ./tests/test_rest_get_bucket_location.sh || exit_code=$?
      ;;
    rest-get-bucket-policy-status)
      echo "Running REST get bucket policy status tests ..."
      "$HOME"/bin/bats ./tests/test_rest_get_bucket_policy_status.sh || exit_code=$?
      ;;
    rest-get-object-tagging)
      echo "Running REST get object tagging tests ..."
      "$HOME"/bin/bats ./tests/test_rest_get_object_tagging.sh || exit_code=$?
      ;;
    rest-head-bucket)
      echo "Running REST head bucket tests ..."
      "$HOME"/bin/bats ./tests/test_rest_head_bucket.sh || exit_code=$?
      ;;
    rest-list-buckets)
      echo "Running REST list-buckets tests ..."
      "$HOME"/bin/bats ./tests/test_rest_list_buckets.sh || exit_code=$?
      ;;
    rest-list-object-versions)
      echo "Running REST list-object-versions tests ..."
      "$HOME"/bin/bats ./tests/test_rest_list_object_versions.sh || exit_code=$?
      ;;
    rest-not-implemented)
      echo "Running REST not-implemented tests ..."
      "$HOME"/bin/bats ./tests/test_rest_not_implemented.sh || exit_code=$?
      ;;
    rest-multipart)
      echo "Running REST multipart tests ..."
      "$HOME"/bin/bats ./tests/test_rest_multipart.sh || exit_code=$?
      ;;
    rest-put-bucket-tagging)
      echo "Running REST put-bucket-tagging tests ..."
      "$HOME"/bin/bats ./tests/test_rest_put_bucket_tagging.sh || exit_code=$?
      ;;
    rest-put-object)
      echo "Running REST put-object tests ..."
      "$HOME"/bin/bats ./tests/test_rest_put_object.sh || exit_code=$?
      ;;
    rest-put-object-tagging)
      echo "Running REST put-object-tagging tests ..."
      "$HOME"/bin/bats ./tests/test_rest_put_object_tagging.sh || exit_code=$?
      ;;
    rest-versioning)
      echo "Running REST versioning tests ..."
      "$HOME"/bin/bats ./tests/test_rest_versioning.sh || exit_code=$?
      ;;
    s3api-user)
      echo "Running s3api user tests ..."
      "$HOME"/bin/bats ./tests/test_user_aws.sh || exit_code=$?
      ;;
    setup-remove-static)
      echo "Testing setup/remove static bucket scripts ..."
      VERSITYGW_TEST_ENV="$VERSITYGW_TEST_ENV" ./tests/test_setup_remove_static.sh || exit_code=$?
      ;;
  esac
  if [ "$exit_code" -ne 0 ]; then
    exit 1
  fi
}

if [ $# -le 0 ]; then
  show_help
  exit 0
fi

IFS=',' read -ra options <<< "$1"
for option in "${options[@]}"; do
  handle_param "$option"
done

# shellcheck disable=SC2086
exit 0
