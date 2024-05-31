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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/s3event"
)

func utilsCommand() *cli.Command {
	return &cli.Command{
		Name:  "utils",
		Usage: "utility helper CLI tool",
		Subcommands: []*cli.Command{
			{
				Name:    "gen-event-filter-config",
				Aliases: []string{"gefc"},
				Usage:   "Create a new configuration file for bucket event notifications filter.",
				Action:  generateEventFiltersConfig,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "path",
						Usage:   "the path where the config file has to be created",
						Aliases: []string{"p"},
					},
				},
			},
		},
	}
}

func generateEventFiltersConfig(ctx *cli.Context) error {
	pathFlag := ctx.String("path")
	path, err := filepath.Abs(filepath.Join(pathFlag, "event_config.json"))
	if err != nil {
		return err
	}

	config := s3event.EventFilter{
		s3event.EventObjectCreated:              true,
		s3event.EventObjectCreatedPut:           true,
		s3event.EventObjectCreatedPost:          true,
		s3event.EventObjectCreatedCopy:          true,
		s3event.EventCompleteMultipartUpload:    true,
		s3event.EventObjectRemoved:              true,
		s3event.EventObjectRemovedDelete:        true,
		s3event.EventObjectRemovedDeleteObjects: true,
		s3event.EventObjectTagging:              true,
		s3event.EventObjectTaggingPut:           true,
		s3event.EventObjectTaggingDelete:        true,
		s3event.EventObjectAclPut:               true,
		s3event.EventObjectRestore:              true,
		s3event.EventObjectRestorePost:          true,
		s3event.EventObjectRestoreCompleted:     true,
	}

	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("parse event config: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(configBytes)
	if err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}
