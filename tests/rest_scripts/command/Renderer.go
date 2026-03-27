package command

type Renderer interface {
	CalculateDateTimeParams()
	DeriveHost() error
	DeriveBucketAndKeyPath()
	PerformPayloadCalculations() error
	DeriveHeaderValues() error
	CalculateSignature() error
	Render() error
}
