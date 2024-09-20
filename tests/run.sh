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
    echo "   -h, --help          Display this help message and exit"
    echo "                       Separate the below by comma"
    echo "   s3api               Run tests with s3api cli"
    echo "   s3api-non-policy    Run policy tests with s3api cli"
    echo "   s3api-policy        Run policy tests with s3api cli"
    echo "   s3                  Run tests with s3 cli"
    echo "   s3cmd               Run tests with s3cmd utility"
    echo "   mc                  Run tests with mc utility"
    echo "   rest                Run tests with rest cli"
    echo "   s3api-user          Run user tests with aws cli"
}

handle_param() {
  case $1 in
      -h|--help)
          show_help
          exit 0
          ;;
      s3|s3api|s3cmd|mc|s3api-user|rest|s3api-policy|s3api-non-policy)
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
      "$HOME"/bin/bats ./tests/test_s3api.sh || exit_code=$?
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_s3api_policy.sh || exit_code=$?
      fi
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_user_aws.sh || exit_code=$?
      fi
      ;;
    s3api-policy)
      echo "Running s3api policy tests ..."
      "$HOME"/bin/bats ./tests/test_s3api_policy.sh || exit_code=$?
      ;;
    s3api-non-policy)
      echo "Running s3api non-policy tests ..."
      "$HOME"/bin/bats ./tests/test_s3api.sh || exit_code=$?
      ;;
    s3)
      echo "Running s3 tests ..."
      "$HOME"/bin/bats ./tests/test_s3.sh || exit_code=$?
      ;;
    s3cmd)
      echo "Running s3cmd tests ..."
      "$HOME"/bin/bats ./tests/test_s3cmd.sh || exit_code=$?
      if [[ $exit_code -eq 0 ]]; then
        "$HOME"/bin/bats ./tests/test_user_s3cmd.sh || exit_code=$?
      fi
      ;;
    mc)
      echo "Running mc tests ..."
      "$HOME"/bin/bats ./tests/test_mc.sh || exit_code=$?
      ;;
    rest)
      echo "Running rest tests ..."
      "$HOME"/bin/bats ./tests/test_rest.sh || exit_code=$?
      ;;
    s3api-user)
      echo "Running s3api user tests ..."
      "$HOME"/bin/bats ./tests/test_user_aws.sh || exit_code=$?
  esac
  if [ $exit_code -ne 0 ]; then
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
