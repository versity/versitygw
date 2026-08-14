// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package private

import (
	"fmt"
	"net"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/internal/netutil"
)

const shutDownDuration = time.Second * 10

// ServeMultiPort binds and serves the private endpoints on every address in
// addrs. Each address is checked with netutil.RequireSecureTransport before
// binding anything — mTLS (server cert + mandatory client-cert
// verification) or a unix socket, nothing else — so a misconfiguration
// fails startup instead of silently serving these endpoints in the clear.
// tlsOpts is only applied to non-unix-socket addresses, or to a unix
// socket address if a server certificate is configured for it too.
func (p *PrivateAPI) ServeMultiPort(addrs []string, tlsOpts netutil.TLSOptions) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no private listener addresses specified")
	}

	hasMTLS := tlsOpts.GetCertificate != nil && tlsOpts.ClientCAs != nil && tlsOpts.RequireClientCert
	for _, addr := range addrs {
		if err := netutil.RequireSecureTransport(addr, hasMTLS); err != nil {
			return err
		}
	}

	var listeners []net.Listener
	for _, addr := range addrs {
		var ln net.Listener
		var err error
		if netutil.IsUnixSocketPath(addr) && tlsOpts.GetCertificate == nil {
			ln, err = netutil.NewMultiAddrListener(fiber.NetworkTCP, addr, netutil.ListenerOptions{SocketPerm: p.socketPerm})
		} else {
			ln, err = netutil.NewMultiAddrTLSListenerWithOptions(fiber.NetworkTCP, addr, tlsOpts, netutil.ListenerOptions{SocketPerm: p.socketPerm})
		}
		if err != nil {
			return fmt.Errorf("failed to bind private iam listener %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
	}

	finalListener := netutil.NewMultiListener(listeners...)
	return p.app.Listener(finalListener, fiber.ListenConfig{DisableStartupMessage: true})
}

// Shutdown gracefully stops the private endpoint listeners.
func (p *PrivateAPI) Shutdown() error {
	return p.app.ShutdownWithTimeout(shutDownDuration)
}
