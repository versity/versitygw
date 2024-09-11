#!/usr/bin/env bash

. ./aws_env_setup.sh

aws s3 mb s3://test
aws s3 cp docker-compose.yml s3://test/test.yaml
