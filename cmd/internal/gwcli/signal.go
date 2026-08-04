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

package gwcli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	// SigDone is signaled once on SIGINT/SIGTERM to begin shutdown.
	SigDone = make(chan struct{}, 1)
	// SigHup is signaled on every SIGHUP to trigger a config reload.
	SigHup = make(chan struct{}, 1)
)

// SetupSignalHandler starts a goroutine that translates SIGINT/SIGTERM into a
// single SigDone notification and SIGHUP into repeated SigHup notifications.
func SetupSignalHandler() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigs {
			fmt.Fprintf(os.Stderr, "caught signal %v\n", sig)
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				SigDone <- struct{}{}
			case syscall.SIGHUP:
				SigHup <- struct{}{}
			}
		}
	}()
}
