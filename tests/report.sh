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

check_and_create_database() {
  # Define SQL commands to create a table
  SQL_CREATE_TABLE="CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command TEXT NOT NULL,
    client TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    UNIQUE(command, client)
  );"

# Execute the SQL commands to create the database and table
sqlite3 "$COVERAGE_DB" <<EOF
$SQL_CREATE_TABLE
.exit
EOF
  log 5 "Database '$COVERAGE_DB' and table 'entries' created successfully."
}

record_command() {
  if [ -z "$COVERAGE_DB" ]; then
    log 5 "no coverage db set, not recording"
    return 0
  fi
  if [[ $# -lt 1 ]]; then
    log 2 "'record command' requires at least command name"
    return 1
  fi
  check_and_create_database
  log 5 "command to record: $1"
  client=""
  #role="root"
  for arg in "${@:2}"; do
    log 5 "Argument: $arg"
    if [[ $arg != *":"* ]]; then
      log 3 "'$arg' must contain colon to record client"
      continue
    fi
    header=$(echo "$arg" | awk -F: '{print $1}')
    case $header in
      "client")
        client=$(echo "$arg" | awk -F: '{print $2}')
        ;;
      *)
        log 3 "unrecognized header: $client"
        ;;
    esac
  done
  if ! error=$(sqlite3 "$COVERAGE_DB" "INSERT INTO entries (command, client, count) VALUES(\"$1\", \"$client\", 1) ON CONFLICT(command, client) DO UPDATE SET count = count + 1" 2>&1); then
    log 2 "error in sqlite statement: $error"
  fi
}

record_result() {
  if [ -z "$COVERAGE_DB" ]; then
    log 5 "no coverage db set, not recording"
    return 0
  fi
  # Define SQL commands to create a table
  SQL_CREATE_TABLE="CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command TEXT NOT NULL,
    client TEXT,
    count INTEGER,
    pass INTEGER DEFAULT 1,
    UNIQUE(command, client)
  );"
  # Execute the SQL commands to create the database and table
  sqlite3 "$COVERAGE_DB" <<EOF
$SQL_CREATE_TABLE
.exit
EOF

  RESULT=$(sqlite3 "$COVERAGE_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='entries';")
  if [ -z "$RESULT" ]; then
    return
  fi

  # Iterate over each command in the entries table
  while IFS="|" read -r command client count; do
    if [[ $BATS_TEST_STATUS -eq 0 ]]; then
      # Test passed
      sqlite3 "$COVERAGE_DB" "INSERT INTO results (command, client, count) VALUES ('$command', '$client', '$count')
                          ON CONFLICT(command, client) DO UPDATE SET count = count + $count;"
    else
      # Test failed
      sqlite3 "$COVERAGE_DB" "INSERT INTO results (command, client, count, pass) VALUES ('$command', '$client', '$count', 0)
                          ON CONFLICT(command, client) DO UPDATE SET count = count + $count;"
    fi
  done < <(sqlite3 "$COVERAGE_DB" "SELECT command, client, count FROM entries;")

  sqlite3 "$COVERAGE_DB" "DROP TABLE entries;"

  log 5 "Database '$COVERAGE_DB' and table 'entries' created successfully."
}