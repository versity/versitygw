// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build linux && cgo && daos

package daos

/*
#cgo LDFLAGS: -ldfs
#include <daos_fs.h>

int versitygw_daos_client_linked(void) {
	void *fns[3];

	fns[0] = (void *)dfs_init;
	fns[1] = (void *)dfs_connect;
	fns[2] = (void *)dfs_move;
	return fns[0] != 0 && fns[1] != 0 && fns[2] != 0;
}
*/
import "C"
import "fmt"

func New(pool, container, sysName string) (*Daos, error) {
	if C.versitygw_daos_client_linked() == 0 {
		return nil, fmt.Errorf("daos client library did not link")
	}
	fs, err := openContainer(pool, sysName, container)
	if err != nil {
		return nil, err
	}
	return NewWithFS(fs), nil
}
