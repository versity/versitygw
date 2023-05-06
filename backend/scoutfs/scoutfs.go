package scoutfs

import (
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/backend/posix"
)

type ScoutFS struct {
	*posix.Posix
}

var _ backend.Backend = ScoutFS{}
