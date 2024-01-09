# Copyright 2023 Versity Software
# This file is licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

BIN=versitygw

VERSION := $(shell if test -e VERSION; then cat VERSION; else git describe --abbrev=0 --tags HEAD; fi)
BUILD := $(shell git rev-parse --short HEAD || echo release-rpm)
TIME := `date -u '+%Y-%m-%d_%I:%M:%S%p'`

LDFLAGS=-ldflags "-X=main.Build=$(BUILD) -X=main.BuildTime=$(TIME) -X=main.Version=$(VERSION)"

all: build

build: $(BIN)

.PHONY: $(BIN)
$(BIN):
	$(GOBUILD) $(LDFLAGS) -o $(BIN) cmd/$(BIN)/*.go

testbin:
	$(GOBUILD) $(LDFLAGS) -o $(BIN) -cover -race cmd/$(BIN)/*.go

.PHONY: test
test: 
	$(GOTEST) ./...

.PHONY: check
check:
# note this requires staticcheck be in your PATH:
# export PATH=$PATH:~/go/bin
# go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...
	golint ./...
	gofmt -s -l .

.PHONY: clean
clean: 
	$(GOCLEAN)

.PHONY: cleanall
cleanall: clean
	rm -f $(BIN)
	rm -f versitygw-*.tar
	rm -f versitygw-*.tar.gz
	rm -f versitygw.spec

%.spec: %.spec.in
	sed -e 's/@@VERSION@@/$(VERSION)/g' < $< > $@+
	mv $@+ $@

TARFILE = $(BIN)-$(VERSION).tar

dist: $(BIN).spec
	echo $(VERSION) >VERSION
	git archive --format=tar --prefix $(BIN)-$(VERSION)/ HEAD > $(TARFILE)
	@ tar rf $(TARFILE) --transform="s@\(.*\)@$(BIN)-$(VERSION)/\1@" $(BIN).spec VERSION
	rm -f VERSION
	rm -f $(BIN).spec
	gzip -f $(TARFILE)

# Creates and runs S3 gateway instance in a docker container
.PHONY: up-posix
up-posix:
	docker compose --env-file .env.dev up posix

# Creates and runs S3 gateway proxy instance in a docker container
.PHONY: up-proxy
up-proxy:
	docker compose --env-file .env.dev up proxy

# Creates and runs S3 gateway to azurite instance in a docker container
.PHONY: up-azurite
up-azurite:
	docker compose --env-file .env.dev up azurite azuritegw

# Creates and runs both S3 gateway and proxy server instances in docker containers
.PHONY: up-app
up-app:
	docker compose --env-file .env.dev up
