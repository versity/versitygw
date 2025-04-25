package plugins

import "github.com/versity/versitygw/backend"

// BackendPlugin defines an interface for creating backend
// implementation instances.
// Plugins implementing this interface can be built as shared
// libraries using Go's plugin system (to build use `go build -buildmode=plugin`).
// The shared library should export an instance of
// this interface in a variable named `Backend`.
type BackendPlugin interface {
	// New creates and initializes a new backend.Backend instance.
	// The config parameter specifies the path of the file containing
	// the configuration for the backend.
	//
	// Implementations of this method should perform the necessary steps to
	// establish a connection to the underlying storage system or service
	// (e.g., network storage system, distributed storage system, cloud storage)
	//  and configure it according to the provided configuration.
	New(config string) (backend.Backend, error)
}
