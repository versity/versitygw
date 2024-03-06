#!/bin/bash

# Function to display help information
show_help() {
    echo "Usage: $0 [option...]"
    echo "   -h, --help          Display this help message and exit"
    echo "   -s, --static        Don't remove buckets between tests"
    echo "   aws                 Run tests with aws cli"
    echo "   aws-posix           Run posix tests with aws cli"
    echo "   s3cmd               Run tests with s3cmd utility"
    echo "   mc                  Run tests with mc utility"
}

handle_param() {
  case $1 in
      -h|--help)
          show_help
          exit 0
          ;;
      -s|--static)
          export RECREATE_BUCKETS=false
          ;;
      aws|aws-posix|s3cmd|mc)
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

export RECREATE_BUCKETS=true
while [[ "$#" -gt 0 ]]; do
  handle_param "$1"
  shift # past argument or value
done

if [[ -z "$VERSITYGW_TEST_ENV" ]]; then
  echo "Error:  VERSITYGW_TEST_ENV parameter must be set"
  exit 1
fi

if [[ $RECREATE_BUCKETS == false ]]; then
  ./tests/setup_static.sh || exit_code=$?
  if [[ exit_code -ne 0 ]]; then
    exit 1
  fi
fi

case $command_type in
  aws)
    "$HOME"/bin/bats ./tests/test_aws.sh || exit_code=$?
    ;;
  aws-posix)
    "$HOME"/bin/bats ./tests/test_aws_posix.sh || exit_code=$?
    ;;
  s3cmd)
    "$HOME"/bin/bats ./tests/test_s3cmd.sh || exit_code=$?
    ;;
  mc)
    "$HOME"/bin/bats ./tests/test_mc.sh || exit_code=$?
    ;;
esac

exit $exit_code
