package auth

import "github.com/versity/scoutgw/s3err"

type IAMConfig struct {
	AccessAccounts map[string]string
}

type IAMService interface {
	GetIAMConfig() (*IAMConfig, error)
}

type IAMServiceUnsupported struct{}

var _ IAMService = &IAMServiceUnsupported{}

func New() IAMService {
	return &IAMServiceUnsupported{}
}

func (IAMServiceUnsupported) GetIAMConfig() (*IAMConfig, error) {
	return nil, s3err.GetAPIError(s3err.ErrNotImplemented)
}
