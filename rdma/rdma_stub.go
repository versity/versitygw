//go:build !(linux && amd64 && cgo)

// Package rdma provides Go bindings to libcuobjserver.
// This file is a stub for platforms without RDMA support.
package rdma

import (
	"errors"
	"unsafe"
)

var errNotSupported = errors.New("rdma: not supported on this platform")

// Buffer wraps an RDMA-registered memory region (stub — always zero-valued).
type Buffer struct {
	hostPtr unsafe.Pointer
	size    int
}

// HostPtr returns the underlying host memory pointer.
func (b *Buffer) HostPtr() unsafe.Pointer { return b.hostPtr }

// Size returns the buffer size in bytes.
func (b *Buffer) Size() int { return b.size }

// Slice returns the buffer contents as a Go byte slice.
func (b *Buffer) Slice() []byte { return []byte{} }

// Server wraps a cuObjServer instance (stub — always returns errNotSupported).
type Server struct{}

// ConfigureTelemetry is a no-op on platforms without RDMA support.
func ConfigureTelemetry(debug bool) {}

// DebugTelemetryEnabled always reports false on stub platforms.
func DebugTelemetryEnabled() bool { return false }

// NewServer always returns errNotSupported on this platform.
func NewServer(ip string, port uint16, tunables *RDMATunables) (*Server, error) {
	return nil, errNotSupported
}

// StartSession always returns errNotSupported on this platform.
func (s *Server) StartSession() error { return errNotSupported }

// InitRDMAConfig always returns errNotSupported on this platform.
func (s *Server) InitRDMAConfig(t RDMATunables) error { return errNotSupported }

// IsConnected always returns false on this platform.
func (s *Server) IsConnected() bool { return false }

// AllocHostBuffer always returns errNotSupported on this platform.
func (s *Server) AllocHostBuffer(size int) (unsafe.Pointer, error) { return nil, errNotSupported }

// FreeHostBuffer is a no-op on this platform.
func (s *Server) FreeHostBuffer(ptr unsafe.Pointer) {}

// RegisterBuffer always returns errNotSupported on this platform.
func (s *Server) RegisterBuffer(ptr unsafe.Pointer, size int) (*Buffer, error) {
	return nil, errNotSupported
}

// DeregisterBuffer is a no-op on this platform.
func (s *Server) DeregisterBuffer(buf *Buffer) {}

// AllocateChannel always returns errNotSupported on this platform.
func (s *Server) AllocateChannel() (uint16, error) { return 0, errNotSupported }

// FreeChannel is a no-op on this platform.
func (s *Server) FreeChannel(id uint16) {}

// HandleGet always returns errNotSupported on this platform.
func (s *Server) HandleGet(key string, buf *Buffer, remoteStart uint64, size int64, rdmaDescr string, channel uint16) (int64, error) {
	return 0, errNotSupported
}

// HandlePut always returns errNotSupported on this platform.
func (s *Server) HandlePut(key string, buf *Buffer, remoteStart uint64, size int64, rdmaDescr string, channel uint16) (int64, error) {
	return 0, errNotSupported
}

// CloseSession is a no-op on this platform.
func (s *Server) CloseSession() {}

// Close is a no-op on this platform.
func (s *Server) Close() {}
