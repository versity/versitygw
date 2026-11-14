package rcdial

import (
	"fmt"
	"net"
	"time"
)

// ErrUnsupportedTransport is returned by the stub transport on
// configurations without the rdma build tag; the caller turns it
// into the 501 unsupported-transport response.
var ErrUnsupportedTransport = fmt.Errorf("rcdial: unsupported transport in this build")

// Config carries the transport limits the gateway sets on the
// adapter; zero fields fall back to the defaults below.
type Config struct {
	// DialTimeout bounds address/route resolution and connection
	// establishment.
	DialTimeout time.Duration
	// TransferTimeout bounds a single RDMA READ/WRITE.
	TransferTimeout time.Duration
	// TeardownTimeout bounds the wait for the peer's disconnect
	// event during Close before tearing down regardless.
	TeardownTimeout time.Duration
}

// DefaultConfig matches the values the adapter constructor applies
// when a zero Config is supplied.
func DefaultConfig() Config {
	return Config{
		DialTimeout:     10 * time.Second,
		TransferTimeout: 60 * time.Second,
		TeardownTimeout: 5 * time.Second,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.DialTimeout == 0 {
		c.DialTimeout = d.DialTimeout
	}
	if c.TransferTimeout == 0 {
		c.TransferTimeout = d.TransferTimeout
	}
	if c.TeardownTimeout == 0 {
		c.TeardownTimeout = d.TeardownTimeout
	}
	return c
}

func (c Config) dialMS() int     { return int(c.DialTimeout.Milliseconds()) }
func (c Config) transferMS() int { return int(c.TransferTimeout.Milliseconds()) }
func (c Config) teardownMS() int { return int(c.TeardownTimeout.Milliseconds()) }

// Dialer is the seam the backend adapter consumes; production binds
// the cgo transport, tests bind fakes. TransportSupport reports
// whether this build can carry v3 transfers at all; the adapter
// answers 501 when it cannot.
type Dialer interface {
	// Dial connects to the token's listener address.
	Dial(t Token) (Conn, error)
	// TransportSupported is false on builds without the rdma
	// transport.
	TransportSupported() bool
}

// Conn is one established connection to a client listener. Staging
// memory for a Read belongs to the connection and is released by the
// returned free function; Write copies the caller's slice into
// C-owned staging internally.
type Conn interface {
	// Read pulls length bytes from the client region; the returned
	// slice aliases connection-owned staging valid until free is
	// called. free is never nil on success.
	Read(length uint64, rkey uint32, remoteAddr uint64) (data []byte, free func(), err error)
	// Write pushes data into the client region; returns the byte
	// count.
	Write(data []byte, rkey uint32, remoteAddr uint64) (int, error)
	// Close disconnects, honoring the teardown deadline.
	Close()
}

// cmDialer is the production dialer over RDMA CM.
type cmDialer struct{ cfg Config }

// stubDialer is the Dialer for builds without the rdma transport.
type stubDialer struct{}

// NewDialer returns the transport dialer; on builds without the
// rdma tag it returns a dialer whose TransportSupported is false
// and whose Dial always fails with ErrUnsupportedTransport.
func NewDialer(cfg Config) Dialer {
	if transportAvailable {
		return cmDialer{cfg: cfg.withDefaults()}
	}
	return stubDialer{}
}

func (stubDialer) TransportSupported() bool { return false }

func (stubDialer) Dial(t Token) (Conn, error) {
	return nil, ErrUnsupportedTransport
}

func (d cmDialer) TransportSupported() bool { return true }

func (d cmDialer) Dial(t Token) (Conn, error) {
	host, portStr, err := net.SplitHostPort(t.ListenAddr())
	if err != nil {
		return nil, fmt.Errorf("rcdial: listener address: %w", err)
	}
	var port uint64
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port == 0 || port > 65535 {
		return nil, fmt.Errorf("rcdial: listener port %q", portStr)
	}
	cn, err := cgoDial(host, uint16(port), d.cfg.dialMS())
	if err != nil {
		return nil, err
	}
	return &connAdapter{c: cn, cfg: d.cfg}, nil
}

type connAdapter struct {
	c   connIface
	cfg Config
}

// connIface is the union the two transports satisfy.
type connIface interface {
	read(localLen uint64, rkey uint32, remoteAddr uint64, timeoutMS int) ([]byte, func(), error)
	write(data []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error)
	close(timeoutMS int)
}

func (a *connAdapter) Read(length uint64, rkey uint32, remoteAddr uint64) ([]byte, func(), error) {
	return a.c.read(length, rkey, remoteAddr, a.cfg.transferMS())
}

func (a *connAdapter) Write(data []byte, rkey uint32, remoteAddr uint64) (int, error) {
	return a.c.write(data, rkey, remoteAddr, a.cfg.transferMS())
}

func (a *connAdapter) Close() {
	a.c.close(a.cfg.teardownMS())
}
