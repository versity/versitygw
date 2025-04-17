// Copyright 2025 Versity Software
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
	vgwplugin "github.com/versity/versitygw/backend/plugin"
)

var (
	pluginPath   string
	pluginConfig string
)

func pluginCommand() *cli.Command {
	return &cli.Command{
		Name:        "plugin",
		Usage:       "plugin storage backend",
		Description: `This tells the gateway to load the backend from a dynamic runtime plugin.`,
		Action:      runPlugin,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "file",
				Usage:       "path to plugin shared object file",
				Value:       "",
				Required:    true,
				EnvVars:     []string{"VGW_PLUGIN_FILE"},
				Destination: &pluginPath,
				Aliases:     []string{"f"},
			},
			&cli.StringFlag{
				Name:        "config",
				Usage:       "configuration option for the plugin",
				Value:       "",
				Required:    true,
				EnvVars:     []string{"VGW_PLUGIN_CONFIG"},
				Destination: &pluginConfig,
				Aliases:     []string{"c"},
			},
		},
	}
}

func runPlugin(ctx *cli.Context) error {
	be, err := vgwplugin.NewPluginBackend(pluginPath, pluginConfig)
	if err != nil {
		return fmt.Errorf("init plugin backend: %w", err)
	}
	return runGateway(ctx.Context, be)
}
