package command

import (
	"errors"
	"fmt"
)

type PutBucketTaggingCommand struct {
	*PutTaggingCommand
}

func NewPutBucketTaggingCommand(s3Command *S3RequestBuilder, fields *TaggingFields) (*PutBucketTaggingCommand, error) {
	if s3Command.Config.BucketName == "" {
		return nil, errors.New("PutBucketTagging must have bucket name")
	}
	command := &PutBucketTaggingCommand{
		&PutTaggingCommand{
			S3RequestBuilder: s3Command,
		},
	}
	if err := command.createTaggingPayload(fields); err != nil {
		return nil, fmt.Errorf("error creating tagging payload: %w", err)
	}
	return command, nil
}
