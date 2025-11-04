package command

type S3CommandConverter interface {
	CurlShellCommand() (string, error)
	OpenSSLCommand() error
}
