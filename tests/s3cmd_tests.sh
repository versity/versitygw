#!/usr/bin/env bats

source ./tests/setup.sh
source ./tests/test_common.sh
source ./tests/util.sh

# test s3cmd bucket creation/deletion
@test "test_create_delete_bucket_s3cmd" {
  test_common_create_delete_bucket "s3cmd"
}

# test listing buckets on versitygw
@test "test_list_buckets_s3cmd" {
  test_common_list_buckets "s3cmd"
}