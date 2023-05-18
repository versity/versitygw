package s3api

import (
	"reflect"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
)

func TestNew(t *testing.T) {
	type args struct {
		app  *fiber.App
		be   backend.Backend
		port string
	}
	tests := []struct {
		name            string
		args            args
		wantS3ApiServer *S3ApiServer
		wantErr         bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotS3ApiServer, err := New(tt.args.app, tt.args.be, tt.args.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotS3ApiServer, tt.wantS3ApiServer) {
				t.Errorf("New() = %v, want %v", gotS3ApiServer, tt.wantS3ApiServer)
			}
		})
	}
}

func TestS3ApiServer_Serve(t *testing.T) {
	tests := []struct {
		name    string
		sa      *S3ApiServer
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.sa.Serve(); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiServer.Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
