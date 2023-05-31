package utils

import (
	"bytes"
	"errors"
	"flag"
	"net/http"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

func GetUserMetaData(headers *fasthttp.RequestHeader) (metadata map[string]string) {
	metadata = make(map[string]string)
	headers.VisitAll(func(key, value []byte) {
		if strings.HasPrefix(string(key), "X-Amz-Meta-") {
			trimmedKey := strings.TrimPrefix(string(key), "X-Amz-Meta-")
			headerValue := string(value)
			metadata[trimmedKey] = headerValue
		}
	})

	return
}

type RootUser struct {
	Login    string
	Password string
}

func GetRootUserCreds() (rootUser RootUser) {
	loginPtr := flag.String("login", "", "Root user login")
	passwordPtr := flag.String("password", "", "Root user password")

	flag.Parse()

	if *loginPtr == "" || *passwordPtr == "" {
		os.Exit(3)
	}

	rootUser = RootUser{
		Login:    *loginPtr,
		Password: *passwordPtr,
	}
	return
}

func CreateHttpRequestFromCtx(ctx *fiber.Ctx) (*http.Request, error) {
	req := ctx.Request()

	httpReq, err := http.NewRequest(string(req.Header.Method()), req.URI().String(), bytes.NewReader(req.Body()))
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}

	// Set the request headers
	req.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if keyStr == "X-Amz-Date" || keyStr == "X-Amz-Content-Sha256" || keyStr == "Host" {
			httpReq.Header.Add(keyStr, string(value))
		}
	})

	// Set the Content-Length header
	httpReq.ContentLength = int64(len(req.Body()))

	// Set the Host header
	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}
