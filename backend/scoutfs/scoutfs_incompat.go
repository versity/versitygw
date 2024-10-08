// Copyright 2023 Versity Software
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

//go:build !(linux && amd64)

package scoutfs

import (
	"errors"
	"fmt"
	"os"

	"github.com/versity/versitygw/auth"
)

func New(rootdir string, opts ScoutfsOpts) (*ScoutFS, error) {
	return nil, fmt.Errorf("scoutfs only available on linux")
}

type tmpfile struct{}

var (
	errNotSupported = errors.New("not supported")
)

func (s *ScoutFS) openTmpFile(_, _, _ string, _ int64, _ auth.Account) (*tmpfile, error) {
	// make these look used for static check
	_ = s.chownuid
	_ = s.chowngid
	_ = s.euid
	_ = s.egid
	return nil, errNotSupported
}

func (tmp *tmpfile) link() error {
	return errNotSupported
}

func (tmp *tmpfile) Write(b []byte) (int, error) {
	return 0, errNotSupported
}

func (tmp *tmpfile) cleanup() {
}

func (tmp *tmpfile) File() *os.File {
	return nil
}

func moveData(_, _ *os.File) error {
	return errNotSupported
}

func statMore(_ string) (stat, error) {
	return stat{}, errNotSupported
}
