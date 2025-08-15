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

setup_acl() {
  if ! check_param_count "setup_acl" "acl file, grantee type, grantee, permission, owner ID" 5 $#; then
    return 1
  fi
  cat <<EOF > "$1"
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
      <ID>$5</ID>
  </Owner>
  <AccessControlList>
      <Grant>
          <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="$2">
              <ID>$3</ID>
          </Grantee>
          <Permission>$4</Permission>
      </Grant>
  </AccessControlList>
</AccessControlPolicy>
EOF
}

setup_acl_json() {
  if [ $# -ne 5 ]; then
    log 2 "'setup_acl_json' requires acl file, grantee type, grantee ID, permission, owner ID"
    return 1
  fi
  cat <<EOF > "$1"
{
  "Grants": [
    {
      "Grantee": {
        "Type": "$2",
        "ID": "$3"
      },
      "Permission": "$4"
    }
  ],
  "Owner": {
    "ID": "$5"
  }
}
EOF
}
