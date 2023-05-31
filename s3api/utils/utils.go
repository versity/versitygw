package utils

import (
	"flag"
	"os"
	"strings"

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
