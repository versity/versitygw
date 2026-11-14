package rcdial

import (
	"fmt"
	"net"
	"time"
)

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

func (c Config) dialMS() int       { return int(c.DialTimeout.Milliseconds()) }
func (c Config) transferMS() int   { return int(c.TransferTimeout.Milliseconds()) }
func (c Config) teardownMS() int   { return int(c.TeardownTimeout.Milliseconds()) }

// Dialer is the seam the backend adapter consumes; production binds
// the cgo transport, tests bind fakes.
type Dialer interface {
	// Dial connects to the token's listener address.
	Dial(t Token) (Conn, error)
}

// Conn is one established connection to a client listener.
type Conn interface {
	// Read pulls len(local) bytes from the client region into
	// local; returns the byte count.
	Read(local []byte, rkey uint32, remoteAddr uint64) (int, error)
	// Write pushes len(local) bytes from local into the client
	// region; returns the byte count.
	Write(local []byte, rkey uint32, remoteAddr uint64) (int, error)
	// Close disconnects, honoring the teardown deadline.
	Close()
}

// CM.Dialer is the production dialer over RDMA CM.
type cmDialer struct{ cfg Config }

// NewDialer returns the transport dialer for cfg.
func NewDialer(cfg Config) Dialer { return cmDialer{cfg: cfg.withDefaults()} }

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
	read(local []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error)
	write(local []byte, rkey uint32, remoteAddr uint64, timeoutMS int) (int, error)
	close(timeoutMS int)
}

func (a *connAdapter) Read(local []byte, rkey uint32, remoteAddr uint64) (int, error) {
	return a.c.read(local, rkey, remoteAddr, a.cfg.transferMS())
}

func (a *connAdapter) Write(local []byte, rkey uint32, remoteAddr uint64) (int, error) {
	return a.c.write(local, rkey, remoteAddr, a.cfg.transferMS())
}

func (a *connAdapter) Close() {
	a.c.close(a.cfg.teardownMS())
}
