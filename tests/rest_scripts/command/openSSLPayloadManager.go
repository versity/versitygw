package command

type OpenSSLPayloadManager interface {
	GetContentLength() (int64, error)
	WritePayload(string) error
}
