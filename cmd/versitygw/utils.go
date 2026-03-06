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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/meta"
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
			{
				Name:    "convert-xattr-metadata",
				Aliases: []string{"cxm"},
				Usage:   "Convert legacy X-Amz-Meta.* xattrs into user.metadata JSON and remove legacy keys.",
				Action:  convertXattrMetadata,
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

const (
	newMetadataAttr = "metadata"   // stored as user.metadata
	oldMetadataHdr  = "X-Amz-Meta" // legacy prefix
)

func convertXattrMetadata(ctx *cli.Context) error {
	root := strings.TrimSpace(ctx.Args().First())
	if root == "" {
		return cli.Exit("missing directory: should be provided as command argument", 2)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve directory: %w", err)
	}

	info, err := os.Stat(absRoot)
	if err != nil {
		return fmt.Errorf("stat directory: %w", err)
	}
	if !info.IsDir() {
		return cli.Exit(fmt.Sprintf("not a directory: %s", absRoot), 2)
	}

	xm := meta.XattrMeta{}
	err = xm.Test(absRoot)
	if err != nil {
		return err
	}

	var (
		scanned   int
		converted int
		skipped   int
		errCount  int
	)

	walkErr := filepath.WalkDir(absRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			errCount++
			// keep going
			return nil
		}

		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			errCount++
			return nil
		}
		if rel == "." {
			// skip root itself
			return nil
		}

		attrs, err := xm.ListAttributes(absRoot, rel)
		if err != nil {
			errCount++
			return nil
		}
		if len(attrs) == 0 {
			// not an s3 object, do not track as skipped
			return nil
		}

		scanned++

		// Collect legacy metadata attributes.
		oldAttrs := make([]string, 0)
		for _, a := range attrs {
			if strings.HasPrefix(a, oldMetadataHdr+".") {
				oldAttrs = append(oldAttrs, a)
			}
		}
		if len(oldAttrs) == 0 {
			skipped++
			return nil
		}

		// Build key/value map from legacy attrs.
		md := make(map[string]string, len(oldAttrs))
		for _, a := range oldAttrs {
			b, err := xm.RetrieveAttribute(nil, absRoot, rel, a)
			if err != nil {
				// If we can't read one key, don't convert this entry.
				errCount++
				return nil
			}
			key := strings.TrimPrefix(a, oldMetadataHdr+".")
			md[key] = string(b)
		}

		// Marshal to JSON and store as user.metadata.
		j, err := json.Marshal(md)
		if err != nil {
			errCount++
			return nil
		}

		if err := xm.StoreAttribute(nil, absRoot, rel, newMetadataAttr, j); err != nil {
			errCount++
			return nil
		}

		// Cleanup old metadata only after successful write of user.metadata.
		for _, a := range oldAttrs {
			if err := xm.DeleteAttribute(absRoot, rel, a); err != nil && !errors.Is(err, meta.ErrNoSuchKey) {
				// Count, but continue cleanup attempts.
				errCount++
			}
		}

		converted++
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("walk directory: %w", walkErr)
	}

	fmt.Printf(
		"xattr metadata conversion is finished:\n  directory: %s\n  scanned: %d\n  converted: %d\n  skipped: %d\n  errors: %d\n",
		absRoot, scanned, converted, skipped, errCount,
	)

	return nil
}
