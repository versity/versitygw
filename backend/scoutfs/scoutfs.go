package scoutfs

import (
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/posix"
)

type ScoutFS struct {
	*posix.Posix
}

var _ backend.Backend = ScoutFS{}
