#!/usr/bin/env bash

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

source ./tests/rest_scripts/rest.sh

deactivate=${DEACTIVATE:=true}

if [ -z "$PYTHON_ENV_FOLDER" ] && [ -z "$TEST_FILE_FOLDER" ]; then
  log_rest 2 "python virtual env setup requires either PYTHON_ENV_FOLDER or TEST_FILE_FOLDER param"
  exit 1
fi
python_env_folder=${PYTHON_ENV_FOLDER:=${TEST_FILE_FOLDER}/env}
if [ ! -d "$python_env_folder" ] && ! python3 -m venv "$python_env_folder"; then
  log_rest 2 "error creating python virtual environment"
  exit 1
fi
if ! source "$python_env_folder/bin/activate"; then
  log_rest 2 "error activating virtual environment"
  exit 1
fi
if ! python3 -m pip list | grep awscrt 1>/dev/null; then
  if ! python3 -m pip install awscrt 1>/dev/null; then
    log_rest 2 "error installing awscrt"
    exit 1
  fi
fi
if [ "$deactivate" == "true" ] && ! deactivate; then
  log_rest 2 "error deactivating"
  exit 1
fi