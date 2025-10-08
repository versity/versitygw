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

//go:build linux && amd64

package scoutfs

import (
	"fmt"
	"os"

	"github.com/versity/scoutfs-go"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/debuglogger"
)

func New(rootdir string, opts ScoutfsOpts) (*ScoutFS, error) {
	metastore := meta.XattrMeta{}

	p, err := posix.New(rootdir, metastore, posix.PosixOpts{
		ChownUID:            opts.ChownUID,
		ChownGID:            opts.ChownGID,
		BucketLinks:         opts.BucketLinks,
		NewDirPerm:          opts.NewDirPerm,
		VersioningDir:       opts.VersioningDir,
		ValidateBucketNames: opts.ValidateBucketNames,
	})
	if err != nil {
		return nil, err
	}

	f, err := os.Open(rootdir)
	if err != nil {
		return nil, fmt.Errorf("open %v: %w", rootdir, err)
	}

	return &ScoutFS{
		Posix:            p,
		rootfd:           f,
		rootdir:          rootdir,
		glaciermode:      opts.GlacierMode,
		disableNoArchive: opts.DisableNoArchive,
	}, nil
}

func moveData(from *os.File, to *os.File) error {
	// May fail if the files are not 4K aligned; check for alignment
	ffi, err := from.Stat()
	if err != nil {
		return fmt.Errorf("stat from: %v", err)
	}
	tfi, err := to.Stat()
	if err != nil {
		return fmt.Errorf("stat to: %v", err)
	}
	if ffi.Size()%4096 != 0 || tfi.Size()%4096 != 0 {
		return os.ErrInvalid
	}

	err = scoutfs.MoveData(from, to)
	if err != nil {
		debuglogger.Logf("ScoutFs MoveData failed: %v", err)
	}
	return err
}

func statMore(path string) (stat, error) {
	st, err := scoutfs.StatMore(path)
	if err != nil {
		return stat{}, err
	}
	var s stat

	s.Meta_seq = st.Meta_seq
	s.Data_seq = st.Data_seq
	s.Data_version = st.Data_version
	s.Online_blocks = st.Online_blocks
	s.Offline_blocks = st.Offline_blocks
	s.Crtime_sec = st.Crtime_sec
	s.Crtime_nsec = st.Crtime_nsec

	return s, nil
}
