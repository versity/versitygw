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

package main

import (
	"fmt"
	"io/fs"
	"math"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/scoutfs"
)

var (
	glacier          bool
	disableNoArchive bool
)

func scoutfsCommand() *cli.Command {
	return &cli.Command{
		Name:  "scoutfs",
		Usage: "scoutfs filesystem storage backend",
		Description: `Support for ScoutFS.
The top level directory for the gateway must be provided. All sub directories
of the top level directory are treated as buckets, and all files/directories
below the "bucket directory" are treated as the objects. The object name is
split on "/" separator to translate to posix storage.
For example:
top level: /mnt/fs/gwroot
bucket: mybucket
object: a/b/c/myobject
will be translated into the file /mnt/fs/gwroot/mybucket/a/b/c/myobject

ScoutFS contains optimizations for multipart uploads using extent
move interfaces as well as support for tiered filesystems.`,
		Action: runScoutfs,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "glacier",
				Usage:       "enable glacier emulation mode",
				Aliases:     []string{"g"},
				EnvVars:     []string{"VGW_SCOUTFS_GLACIER"},
				Destination: &glacier,
			},
			&cli.BoolFlag{
				Name:        "chuid",
				Usage:       "chown newly created files and directories to client account UID",
				EnvVars:     []string{"VGW_CHOWN_UID"},
				Destination: &chownuid,
			},
			&cli.BoolFlag{
				Name:        "chgid",
				Usage:       "chown newly created files and directories to client account GID",
				EnvVars:     []string{"VGW_CHOWN_GID"},
				Destination: &chowngid,
			},
			&cli.BoolFlag{
				Name:        "bucketlinks",
				Usage:       "allow symlinked directories at bucket level to be treated as buckets",
				EnvVars:     []string{"VGW_BUCKET_LINKS"},
				Destination: &bucketlinks,
			},
			&cli.UintFlag{
				Name:        "dir-perms",
				Usage:       "default directory permissions for new directories",
				EnvVars:     []string{"VGW_DIR_PERMS"},
				Destination: &dirPerms,
				DefaultText: "0755",
				Value:       0755,
			},
			&cli.BoolFlag{
				Name:        "disable-noarchive",
				Usage:       "disable setting noarchive for multipart part uploads",
				EnvVars:     []string{"VGW_DISABLE_NOARCHIVE"},
				Destination: &disableNoArchive,
			},
		},
	}
}

func runScoutfs(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return fmt.Errorf("no directory provided for operation")
	}

	if dirPerms > math.MaxUint32 {
		return fmt.Errorf("invalid directory permissions: %d", dirPerms)
	}

	var opts scoutfs.ScoutfsOpts
	opts.GlacierMode = glacier
	opts.ChownUID = chownuid
	opts.ChownGID = chowngid
	opts.BucketLinks = bucketlinks
	opts.NewDirPerm = fs.FileMode(dirPerms)
	opts.DisableNoArchive = disableNoArchive

	be, err := scoutfs.New(ctx.Args().Get(0), opts)
	if err != nil {
		return fmt.Errorf("init scoutfs: %v", err)
	}

	return runGateway(ctx.Context, be)
}
