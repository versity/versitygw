#!/bin/bash

if ! ./tests/run.sh; then
  exit 1
fi
if ! ./tests/run_static.sh; then
  exit 1
fi