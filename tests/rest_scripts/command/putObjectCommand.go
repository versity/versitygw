package command

import (
	"errors"
)

func NewPutObjectCommand(s3Command *S3Command) (*S3Command, error) {
	if s3Command.BucketName == "" {
		return nil, errors.New("PutObject must have bucket name")
	}
	if s3Command.ObjectKey == "" {
		return nil, errors.New("PutObject must have object key")
	}
	s3Command.Method = "PUT"
	s3Command.Query = ""
	return s3Command, nil
}
