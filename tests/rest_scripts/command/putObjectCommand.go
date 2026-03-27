package command

import (
	"errors"
)

func NewPutObjectCommand(s3Command *S3RequestBuilder) (*S3RequestBuilder, error) {
	if s3Command.Config.BucketName == "" {
		return nil, errors.New("PutObject must have bucket name")
	}
	if s3Command.Config.ObjectKey == "" {
		return nil, errors.New("PutObject must have object key")
	}
	s3Command.Config.Method = "PUT"
	s3Command.Config.Query = ""
	return s3Command, nil
}
