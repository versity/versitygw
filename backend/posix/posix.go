package posix

import (
	"github.com/versity/scoutgw/backend"
)

type Posix struct {
	backend.BackendUnsupported
}

var _ backend.Backend = &Posix{}
