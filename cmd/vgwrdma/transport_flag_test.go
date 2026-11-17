// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

package main

import (
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

// The rc-transport flag must accept exactly the two transports the
// dialer knows (plus the empty default) and reject anything else at
// startup, before any gateway listener opens. The test drives the
// real CLI constructor so the Before hook runs the same code the
// binary runs.
func TestRcTransportValidation(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{"", true},
		{"cm", true},
		{"oob", true},
		{"bogus", false},
		{"OOB", false},
		{"cm ", false},
	} {
		app := initApp()
		// The value must ride the actual command line: setting the
		// destination variable directly would be reset by flag
		// parsing before Before runs.
		args := []string{"vgwrdma"}
		if tc.value != "" {
			args = append(args, "--rc-transport", tc.value)
		}
		// "help" skips the gateway-command branch (no rdma flags
		// needed) but still runs the transport validation.
		args = append(args, "help")
		err := app.Run(args)
		if tc.ok && err != nil {
			t.Errorf("rc-transport %q: unexpected error: %v", tc.value, err)
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("rc-transport %q: expected error, got nil", tc.value)
			} else if !strings.Contains(err.Error(), "rc-transport") {
				t.Errorf("rc-transport %q: error does not name the flag: %v", tc.value, err)
			}
		}
	}
}

// The flag must be registered on the app so the validation above is
// reachable from the command line and the env var.
func TestRcTransportFlagRegistered(t *testing.T) {
	app := initApp()
	for _, fl := range app.Flags {
		if names := fl.Names(); len(names) > 0 && names[0] == "rc-transport" {
			if sf, ok := fl.(*cli.StringFlag); ok {
				if len(sf.EnvVars) == 0 || sf.EnvVars[0] != "VGW_RC_TRANSPORT" {
					t.Errorf("rc-transport env vars = %v, want VGW_RC_TRANSPORT", sf.EnvVars)
				}
				return
			}
			t.Fatalf("rc-transport flag is not a StringFlag: %T", fl)
		}
	}
	t.Fatal("rc-transport flag not registered")
}
