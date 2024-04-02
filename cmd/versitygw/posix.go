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

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/posix"
)

var (
	chownuid, chowngid bool
)

func posixCommand() *cli.Command {
	return &cli.Command{
		Name:  "posix",
		Usage: "posix filesystem storage backend",
		Description: `Any posix filesystem that supports extended attributes. The top level
directory for the gateway must be provided. All sub directories of the
top level directory are treated as buckets, and all files/directories
below the "bucket directory" are treated as the objects. The object
name is split on "/" separator to translate to posix storage.
For example:
top level: /mnt/fs/gwroot
bucket: mybucket
object: a/b/c/myobject
will be translated into the file /mnt/fs/gwroot/mybucket/a/b/c/myobject`,
		Action: runPosix,
		Flags: []cli.Flag{
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
		},
	}
}

func runPosix(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return fmt.Errorf("no directory provided for operation")
	}

	be, err := posix.New(ctx.Args().Get(0), posix.PosixOpts{
		ChownUID: chownuid,
		ChownGID: chowngid,
	})
	if err != nil {
		return fmt.Errorf("init posix: %v", err)
	}

	return runGateway(ctx.Context, be)
}
