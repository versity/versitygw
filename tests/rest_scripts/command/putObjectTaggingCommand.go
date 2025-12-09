package command

import (
	"errors"
	"fmt"
)

type PutObjectTaggingCommand struct {
	*PutTaggingCommand
}

func NewPutObjectTaggingCommand(s3Command *S3Command, fields *TaggingFields) (*PutObjectTaggingCommand, error) {
	if s3Command.BucketName == "" {
		return nil, errors.New("PutObjectTagging must have bucket name")
	}
	if s3Command.ObjectKey == "" {
		return nil, errors.New("PutObjectTagging must have object key")
	}
	command := &PutObjectTaggingCommand{
		&PutTaggingCommand{
			S3Command: s3Command,
		},
	}
	if err := command.createTaggingPayload(fields); err != nil {
		return nil, fmt.Errorf("error creating tagging payload: %w", err)
	}
	return command, nil
}
