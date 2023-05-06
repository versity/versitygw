package s3api

import (
	"github.com/versity/scoutgw/backend"
)

type S3ApiServer struct {
	be   backend.Backend
	port int
}

func New(be backend.Backend, port int) (s3ApiServer *S3ApiServer, err error) {
	s3ApiServer = &S3ApiServer{
		be:   be,
		port: port,
	}

	return s3ApiServer, nil
}
