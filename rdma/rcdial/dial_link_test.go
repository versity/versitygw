//go:build linux && amd64 && cgo && rdma

package rcdial

import (
	"os"
	"testing"
	"time"
)

// TestLinkSmoke proves the tagged package compiles and links against
// the wrapper archive and the verbs/rdmacm libraries, and that the
// production dialer at least rejects an unreachable listener within
// its deadline. The runtime dial assertion only runs when
// RDIAL_TEST_LINK=1: CI and hosts without a usable RDMA device can
// still compile- and link-check the transport (the build itself is
// the gate; this env guard only skips the live-dial assertion).
func TestLinkSmoke(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DialTimeout = 500 * time.Millisecond
	d := NewDialer(cfg)

	tok := Token{
		ListenIP:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1},
		ListenPort: 1, // reserved port: nothing dials this
		RKey:       1,
		RemoteAddr: 0,
		Length:     1,
	}
	if os.Getenv("RDIAL_TEST_LINK") != "1" {
		t.Skip("set RDIAL_TEST_LINK=1 to run the live dial assertion")
	}
	start := time.Now()
	if _, err := d.Dial(tok); err == nil {
		t.Fatal("dial to port 1 unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("dial to unreachable port took %v; deadline not honored", elapsed)
	}
}
