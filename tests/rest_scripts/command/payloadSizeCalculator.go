package command

type PayloadSizeCalculator interface {
	CalculatePayloadSize() int64
}
