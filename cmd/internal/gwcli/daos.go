// Copyright 2026 Versity Software
// Copyright 2026 Gluesys
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

package gwcli

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/daos"
)

// DaosCommand returns the "daos" subcommand, common to all versitygw binaries.
func DaosCommand() *cli.Command {
	return &cli.Command{
		Name:  "daos",
		Usage: "DAOS POSIX container storage backend",
		Description: `Open one existing DAOS pool and one existing POSIX container.
This command does not create pools or containers.`,
		Action: runDaos,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "pool",
				Usage:    "DAOS pool label",
				EnvVars:  []string{"VGW_DAOS_POOL"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "container",
				Usage:    "DAOS POSIX container label",
				EnvVars:  []string{"VGW_DAOS_CONTAINER"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "sys-name",
				Usage:   "DAOS system name (empty uses the default system)",
				EnvVars: []string{"VGW_DAOS_SYS_NAME"},
			},
		},
	}
}

func runDaos(ctx *cli.Context) error {
	pool := ctx.String("pool")
	container := ctx.String("container")
	if pool == "" || container == "" {
		return fmt.Errorf("pool and container are required")
	}

	be, err := daos.New(pool, container, ctx.String("sys-name"))
	if err != nil {
		return fmt.Errorf("init daos: %w", err)
	}

	return RunGateway(ctx.Context, be)
}
