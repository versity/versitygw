package rcobj

// Error codes mirrored from hipobj.h. Defined in a build-tag-free
// file so callers compare OpError codes under the cgo and stub
// builds alike.
const (
	OpSuccess            = 0
	OpInvalidValue       = 1
	OpNotInitialized     = 2
	OpAlreadyInitialized = 3
	OpRdmaError          = 4
	OpS3Error            = 5
	OpBufNotRegistered   = 6
	OpBufAlreadyReg      = 7
	OpNicNotFound        = 8
	OpDmabufNotSupported = 9
	OpSizeTooLarge       = 10
	OpInternalError      = 11
	OpNotSupported       = 12
	OpBusy               = 13
)
