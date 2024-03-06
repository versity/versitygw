#!/usr/bin/env bats

source ./tests/test_common.sh
source ./tests/setup.sh

# test mc bucket creation/deletion
@test "test_create_delete_bucket_mc" {
  test_common_create_delete_bucket "mc"
}