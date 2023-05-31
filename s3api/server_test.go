package s3api

import (
	"reflect"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/scoutgw/backend"
	"github.com/versity/scoutgw/s3api/utils"
)

func TestNew(t *testing.T) {
	type args struct {
		app      *fiber.App
		be       backend.Backend
		port     string
		rootUser utils.RootUser
	}

	app := fiber.New()
	be := backend.BackendUnsupported{}
	router := S3ApiRouter{}
	port := ":7070"

	tests := []struct {
		name            string
		args            args
		wantS3ApiServer *S3ApiServer
		wantErr         bool
	}{
		{
			name: "Create S3 api server",
			args: args{
				app:      app,
				be:       be,
				port:     port,
				rootUser: utils.RootUser{},
			},
			wantS3ApiServer: &S3ApiServer{
				app:     app,
				port:    port,
				router:  &router,
				backend: be,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotS3ApiServer, err := New(tt.args.app, tt.args.be, tt.args.port, tt.args.rootUser)
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
		{
			name:    "Return error when serving S3 api server with invalid address",
			wantErr: true,
			sa: &S3ApiServer{
				app:     fiber.New(),
				backend: backend.BackendUnsupported{},
				port:    "Wrong address",
				router:  &S3ApiRouter{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.sa.Serve(); (err != nil) != tt.wantErr {
				t.Errorf("S3ApiServer.Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
