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

// Package gwcli holds the versitygw CLI subcommands and state shared by all
// versitygw-based main packages (cmd/versitygw, cmd/vgwrdma, ...). Hosting
// binaries wire up their backend-specific flags/commands in their own main
// package, and delegate the identical, backend-agnostic subcommands here.
package gwcli

import (
	"context"

	"github.com/versity/versitygw/backend"
)

// RootUserAccess and RootUserSecret are the root user credentials parsed by
// the hosting binary's --access/--secret flags. The admin subcommand falls
// back to these when no admin-specific credentials are provided.
var (
	RootUserAccess string
	RootUserSecret string
)

// CopyObjectThreshold is the maximum allowed source object size in bytes for
// CopyObject, populated by the hosting binary's --copy-object-threshold flag.
var CopyObjectThreshold int64

// DisableStrictBucketNames allows relaxed bucket naming, populated by the
// hosting binary's --disable-strict-bucket-names flag.
var DisableStrictBucketNames bool

// RunGateway starts the S3 gateway server for the given backend. The hosting
// binary's main package must set this before running any command that can
// launch a backend (azure, plugin, s3).
var RunGateway func(ctx context.Context, be backend.Backend) error
