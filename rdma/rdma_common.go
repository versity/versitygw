package rdma

// MaxTransferSize is the cuObjServer limit per RDMA operation (1 GiB).
const MaxTransferSize = 1 << 30

// RDMATunables holds RDMA connection tuning parameters that map to
// cuObjRDMATunableParam. Pass a non-nil pointer in CuServerOpts to apply
// custom settings before the RDMA session starts; nil means library defaults.
//
// Use DefaultRDMATunables() to start from the library defaults and adjust
// only the fields you care about.
type RDMATunables struct {
	// NumDCIs controls the maximum number of concurrent RDMA connections
	// (Dynamic Connection Interfaces). Default: 128.
	NumDCIs int
	// CQDepth is the completion queue depth, limiting outstanding ops.
	// Default: 640.
	CQDepth uint32
	// DCKey is the InfiniBand Dynamic Connection security key. All clients
	// must use a matching key. Change this from the default in production.
	// Default: 0xffeeddcc.
	DCKey uint64
	// ServiceLevel sets the IB QoS service level. Default: 0.
	ServiceLevel int
	// Timeout is the QP ACK timeout exponent: 4.096 * 2^Timeout µs.
	// Default: 16 (~268 ms).
	Timeout uint8
	// HopLimit is the IB packet hop limit (analogous to IP TTL). Default: 4.
	HopLimit uint32
	// PKeyIndex is the IB partition key index. Default: 0.
	PKeyIndex int
	// DelayInterval is the polling delay in nanoseconds. Default: 5000.
	DelayInterval uint32
	// DelayMode selects the polling strategy:
	//   0 = none, 1 = batch (default), 2 = per-entry, 3 = adaptive.
	DelayMode int
	// RetryCount is the QP retry count (0–7). Default: 7.
	RetryCount uint8
	// QPResetOnFailure controls whether the QP is reset after an RDMA failure.
	// Default: true.
	QPResetOnFailure bool
	// TrafficClass sets the IB traffic class / DSCP bits. Default: 96.
	TrafficClass uint32
	// MaxRdAtomic is the max outstanding RDMA reads per DCI QP.
	// 0 means auto-detect from device capabilities. Default: 0.
	MaxRdAtomic int
}

// DefaultRDMATunables returns a RDMATunables pre-populated with the
// cuObjServer library defaults. Use this as a starting point and override
// only the fields you need.
func DefaultRDMATunables() RDMATunables {
	return RDMATunables{
		NumDCIs:          128,
		CQDepth:          640,
		DCKey:            0xffeeddcc,
		ServiceLevel:     0,
		Timeout:          16,
		HopLimit:         4,
		PKeyIndex:        0,
		DelayInterval:    5000,
		DelayMode:        1, // CUOBJ_DELAY_BATCH
		RetryCount:       7,
		QPResetOnFailure: true,
		TrafficClass:     96,
		MaxRdAtomic:      0,
	}
}
