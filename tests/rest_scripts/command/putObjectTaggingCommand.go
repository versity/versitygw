package command

import (
	"errors"
	"fmt"
)

type PutObjectTaggingCommand struct {
	*PutTaggingCommand
}

func NewPutObjectTaggingCommand(s3Command *S3RequestBuilder, fields *TaggingFields) (*PutObjectTaggingCommand, error) {
	if s3Command.Config.BucketName == "" {
		return nil, errors.New("PutObjectTagging must have bucket name")
	}
	if s3Command.Config.ObjectKey == "" {
		return nil, errors.New("PutObjectTagging must have object key")
	}
	command := &PutObjectTaggingCommand{
		&PutTaggingCommand{
			S3RequestBuilder: s3Command,
		},
	}
	if err := command.createTaggingPayload(fields); err != nil {
		return nil, fmt.Errorf("error creating tagging payload: %w", err)
	}
	return command, nil
}
