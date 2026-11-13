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

package daos

import "errors"

// initRef is one successful dfs_init owned by one connection attempt.
type initRef struct {
	held bool
}

func acquireInit(init func() error) (initRef, error) {
	if err := init(); err != nil {
		return initRef{}, err
	}
	return initRef{held: true}, nil
}

// release disconnects this handle and releases its own init reference.
// A second call does nothing. A failed disconnect is still returned,
// and this reference is still released.
func (r *initRef) release(disconnect, fini func() error) error {
	if r == nil || !r.held {
		return nil
	}
	var derr error
	if disconnect != nil {
		derr = disconnect()
	}
	r.held = false
	var ferr error
	if fini != nil {
		ferr = fini()
	}
	return errors.Join(derr, ferr)
}
