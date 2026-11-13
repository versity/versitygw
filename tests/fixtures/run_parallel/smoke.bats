#!/usr/bin/env bats

# Copyright 2026 Versity Software
# SPDX-License-Identifier: Apache-2.0

@test "pass-suite" {
  [ -f /home/tester/config/.env ]
  printf '%s\n' "Smoke test reached the mounted log folder" > /home/tester/log/fixture.log
}

@test "fail-suite" {
  false
}
