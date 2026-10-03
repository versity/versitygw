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

	go forwardSignals(sigs, SigDone, SigHup)
}

// forwardSignals relays sigs into done and hup without ever blocking. Every
// subcommand installs this handler, but only some of them read hup, so a
// blocking send would park this goroutine on the second SIGHUP and every
// SIGINT/SIGTERM after it would be lost. A notification already pending
// covers the new one: a reload re-reads everything it reloads, and shutdown
// only needs to start once.
func forwardSignals(sigs <-chan os.Signal, done, hup chan<- struct{}) {
	for sig := range sigs {
		fmt.Fprintf(os.Stderr, "caught signal %v\n", sig)
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			notify(done)
		case syscall.SIGHUP:
			notify(hup)
		}
	}
}

func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
