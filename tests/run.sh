#!/bin/bash

# Function to display help information
show_help() {
    echo "Usage: $0 [option...]"
    echo "   -h, --help          Display this help message and exit"
    echo "   -s, --static        Don't remove buckets between tests"
    echo "   aws                 Run tests with aws (s3api) cli"
    echo "   s3api               Run tests with s3api cli"
    echo "   s3                  Run tests with s3 cli"
    echo "   s3cmd               Run tests with s3cmd utility"
    echo "   mc                  Run tests with mc utility"
    echo "   aws-user            Run user tests with aws cli"
}

handle_param() {
  case $1 in
      -h|--help)
          show_help
          exit 0
          ;;
      s3|s3api|aws|s3cmd|mc|aws-user)
          set_command_type "$1"
          ;;
      *) # Handle unrecognized options or positional arguments
          echo "Unrecognized option: $1" >&2
          exit 1
          ;;
  esac
}

set_command_type() {
  if [[ -n $command_type ]]; then
    echo "Error:  command type already set"
    exit 1
  fi
  command_type=$1
  export command_type
}

while [[ "$#" -gt 0 ]]; do
  handle_param "$1"
  shift # past argument or value
done

if [[ -z "$VERSITYGW_TEST_ENV" ]] && [[ $BYPASS_ENV_FILE != "true" ]]; then
  echo "Error:  VERSITYGW_TEST_ENV parameter must be set, or BYPASS_ENV_FILE must be set to true"
  exit 1
fi

case $command_type in
  s3api|aws)
    echo "Running aws tests ..."
    "$HOME"/bin/bats ./tests/test_s3api.sh || exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
      "$HOME"/bin/bats ./tests/test_user_aws.sh || exit_code=$?
    fi
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
  aws-user)
    echo "Running aws user tests ..."
    "$HOME"/bin/bats ./tests/test_user_aws.sh || exit_code=$?
esac

# shellcheck disable=SC2086
exit $exit_code
