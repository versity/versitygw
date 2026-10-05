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

package gwcli

import (
	"context"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend"
)

func TestDaosCommandDoesNotStartWhenOpenFails(t *testing.T) {
	called := false
	prev := RunGateway
	RunGateway = func(context.Context, backend.Backend) error {
		called = true
		return nil
	}
	t.Cleanup(func() { RunGateway = prev })

	app := &cli.App{Commands: []*cli.Command{DaosCommand()}}
	err := app.Run([]string{"versitygw", "daos", "--pool", "pool", "--container", "container", "--sys-name", "sys"})
	if err == nil {
		t.Fatal("command succeeded")
	}
	if !strings.Contains(err.Error(), "-tags daos") && !strings.Contains(err.Error(), "dfs ") && !strings.Contains(err.Error(), "open daos") {
		t.Fatalf("error %q", err)
	}
	if called {
		t.Fatal("gateway started")
	}
}

func TestDaosCommandRequiresPoolAndContainer(t *testing.T) {
	app := &cli.App{Commands: []*cli.Command{DaosCommand()}}
	err := app.Run([]string{"versitygw", "daos", "--pool", "pool"})
	if err == nil {
		t.Fatal("command succeeded without --container")
	}
	if strings.Contains(err.Error(), "-tags daos") {
		t.Fatalf("missing flag reached New: %v", err)
	}
}
