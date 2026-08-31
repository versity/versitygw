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

# docker-compose
DCCMD=docker-compose
DOCKERCOMPOSE=$(DCCMD) -f tests/docker-compose.yml --env-file .env.dev --project-directory .

BIN=versitygw
VGWRDMA_BIN=vgwrdma
VGWRDMA_CMD=./cmd/vgwrdma
VGWRDMA_BUILDER_DOCKERFILE ?= build/vgwrdma-builder/Dockerfile
VGWRDMA_BUILDER_IMAGE ?= vgwrdma-builder:local
VGWRDMA_BUILDER_PLATFORM ?= linux/amd64
CUOBJTEST_BIN=cuobjtest
CUOBJTEST_CMD=./cmd/cuobjtest
CUOBJTEST_HOST_TAG ?= cuobjclient_host
CUOBJTEST_GPU_BUILDER_DOCKERFILE ?= build/cuobjtest-gpu-builder/Dockerfile
CUOBJTEST_GPU_BUILDER_IMAGE ?= cuobjtest-gpu-builder:local
CUOBJTEST_GPU_BUILDER_PLATFORM ?= linux/amd64
CUOBJTEST_HOST_BUILDER_DOCKERFILE ?= build/cuobjtest-host-builder/Dockerfile
CUOBJTEST_HOST_BUILDER_IMAGE ?= cuobjtest-host-builder:local
CUOBJTEST_HOST_BUILDER_PLATFORM ?= linux/amd64

# RDMA build dependencies (Linux/amd64 + cgo)
CUOBJ_LIB_DIR ?= /usr/local/cuda-13.3/targets/x86_64-linux/lib
CUOBJ_SERVER_INC_DIR ?= /usr/include
CUOBJ_CLIENT_INC_DIR ?= /usr/include
CUOBJ_CUDA_INC_DIR ?= /usr/local/cuda/include
CXX ?= g++
AR ?= ar

# Static archive for the cuObjServer C++ wrapper used by the RDMA gateway.
VGWRDMA_WRAPPER_LIB=rdma/libcuobjwrapper.a
VGWRDMA_RDMA_CGO_CFLAGS=-I$(CUOBJ_SERVER_INC_DIR)
VGWRDMA_RDMA_CGO_LDFLAGS=-L$(CUOBJ_LIB_DIR) -Wl,-rpath,$(CUOBJ_LIB_DIR)
CUOBJCLIENT_WRAPPER_LIB=rdma/libcuobjclientwrapper.a
CUOBJCLIENT_CGO_CFLAGS=-I$(CUOBJ_CLIENT_INC_DIR) -I$(CUOBJ_CUDA_INC_DIR)
CUOBJCLIENT_CGO_LDFLAGS=-L$(CUOBJ_LIB_DIR) -Wl,-rpath,$(CUOBJ_LIB_DIR)
HOSTCLIENT_WRAPPER_LIB=rdma/libhostclientwrapper.a
RCSERVER_LIB=rdma/librcserver.a
RCSERVER_SRCS=$(wildcard cuwrapper/rc/*.cpp)
RCSERVER_OBJS=$(RCSERVER_SRCS:.cpp=.o)
RCSERVER_CXXFLAGS=-fPIC -std=c++17 -Icuwrapper/rc

VERSION := $(shell if test -e VERSION; then cat VERSION; else git describe --abbrev=0 --tags HEAD; fi)
BUILD := $(shell git rev-parse --short HEAD || echo release-rpm)
TIME := `date -u '+%Y-%m-%d_%I:%M:%S%p'`

LDFLAGS=-ldflags "-X=main.Build=$(BUILD) -X=main.BuildTime=$(TIME) -X=main.Version=$(VERSION)"

all: build

build: $(BIN)

.PHONY: $(BIN)
$(BIN):
	$(GOBUILD) $(LDFLAGS) -o $(BIN) cmd/$(BIN)/*.go

$(VGWRDMA_WRAPPER_LIB): cuwrapper/cuobjserver_wrapper.cpp cuwrapper/cuobjserver_wrapper.h
	$(CXX) -c -fPIC \
		-I$(CUOBJ_SERVER_INC_DIR) -Icuwrapper \
		-o cuwrapper/cuobjserver_wrapper.o \
		cuwrapper/cuobjserver_wrapper.cpp
	$(AR) rcs $(VGWRDMA_WRAPPER_LIB) cuwrapper/cuobjserver_wrapper.o
	rm -f cuwrapper/cuobjserver_wrapper.o

$(CUOBJCLIENT_WRAPPER_LIB): cuwrapper/cuobjclient_wrapper.cpp cuwrapper/cuobjclient_wrapper.h
	$(CXX) -c -fPIC \
		-I$(CUOBJ_CLIENT_INC_DIR) -I$(CUOBJ_CUDA_INC_DIR) -Icuwrapper \
		-o cuwrapper/cuobjclient_wrapper.o \
		cuwrapper/cuobjclient_wrapper.cpp
	$(AR) rcs $(CUOBJCLIENT_WRAPPER_LIB) cuwrapper/cuobjclient_wrapper.o
	rm -f cuwrapper/cuobjclient_wrapper.o

$(HOSTCLIENT_WRAPPER_LIB): cuwrapper/rdma_host_client_wrapper.cpp cuwrapper/rdma_host_client_wrapper.h
	$(CXX) -c -fPIC \
		-Icuwrapper \
		-o cuwrapper/rdma_host_client_wrapper.o \
		cuwrapper/rdma_host_client_wrapper.cpp
	$(AR) rcs $(HOSTCLIENT_WRAPPER_LIB) cuwrapper/rdma_host_client_wrapper.o
	rm -f cuwrapper/rdma_host_client_wrapper.o

$(RCSERVER_LIB): $(RCSERVER_OBJS)
	$(AR) rcs $@ $^
	rm -f $(RCSERVER_OBJS)

cuwrapper/rc/%.o: cuwrapper/rc/%.cpp
	$(CXX) $(RCSERVER_CXXFLAGS) -c -o $@ $<

.INTERMEDIATE: $(RCSERVER_OBJS)

.PHONY: vgwrdma
vgwrdma: $(VGWRDMA_WRAPPER_LIB) $(RCSERVER_LIB)
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(VGWRDMA_RDMA_CGO_CFLAGS)" \
	CGO_LDFLAGS="$(VGWRDMA_RDMA_CGO_LDFLAGS)" \
		$(GOBUILD) -buildvcs=false $(LDFLAGS) -o $(VGWRDMA_BIN) $(VGWRDMA_CMD)

.PHONY: cuobjtest
cuobjtest: cuobjtest-gpu

.PHONY: cuobjtest-gpu
cuobjtest-gpu: $(CUOBJCLIENT_WRAPPER_LIB)
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CUOBJCLIENT_CGO_CFLAGS)" \
	CGO_LDFLAGS="$(CUOBJCLIENT_CGO_LDFLAGS)" \
		$(GOBUILD) -buildvcs=false $(LDFLAGS) -o $(CUOBJTEST_BIN) $(CUOBJTEST_CMD)

.PHONY: cuobjtest-host
cuobjtest-host: $(HOSTCLIENT_WRAPPER_LIB)
	CGO_ENABLED=1 \
		$(GOBUILD) -buildvcs=false -tags $(CUOBJTEST_HOST_TAG) $(LDFLAGS) -o $(CUOBJTEST_BIN) $(CUOBJTEST_CMD)

.PHONY: vgwrdma-builder-image
vgwrdma-builder-image:
	docker build --platform $(VGWRDMA_BUILDER_PLATFORM) -f $(VGWRDMA_BUILDER_DOCKERFILE) -t $(VGWRDMA_BUILDER_IMAGE) .

.PHONY: vgwrdma-docker
vgwrdma-docker: vgwrdma-builder-image
	docker run --rm --platform $(VGWRDMA_BUILDER_PLATFORM) -v "$(CURDIR)":/workspace -w /workspace $(VGWRDMA_BUILDER_IMAGE)

.PHONY: cuobjtest-gpu-builder-image
cuobjtest-gpu-builder-image:
	docker build --platform $(CUOBJTEST_GPU_BUILDER_PLATFORM) -f $(CUOBJTEST_GPU_BUILDER_DOCKERFILE) -t $(CUOBJTEST_GPU_BUILDER_IMAGE) .

.PHONY: cuobjtest-gpu-docker
cuobjtest-gpu-docker: cuobjtest-gpu-builder-image
	docker run --rm --platform $(CUOBJTEST_GPU_BUILDER_PLATFORM) \
		-v "$(CURDIR)":/workspace \
		-w /workspace $(CUOBJTEST_GPU_BUILDER_IMAGE)

.PHONY: cuobjtest-host-builder-image
cuobjtest-host-builder-image:
	docker build --platform $(CUOBJTEST_HOST_BUILDER_PLATFORM) -f $(CUOBJTEST_HOST_BUILDER_DOCKERFILE) -t $(CUOBJTEST_HOST_BUILDER_IMAGE) .

.PHONY: cuobjtest-host-docker
cuobjtest-host-docker: cuobjtest-host-builder-image
	docker run --rm --platform $(CUOBJTEST_HOST_BUILDER_PLATFORM) \
		-v "$(CURDIR)":/workspace \
		-w /workspace $(CUOBJTEST_HOST_BUILDER_IMAGE)

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
	rm -f $(VGWRDMA_BIN)
	rm -f $(CUOBJTEST_BIN)
	rm -f $(VGWRDMA_WRAPPER_LIB)
	rm -f $(CUOBJCLIENT_WRAPPER_LIB)
	rm -f $(HOSTCLIENT_WRAPPER_LIB)
	rm -f $(RCSERVER_LIB)
	rm -f versitygw-*.tar
	rm -f versitygw-*.tar.gz

TARFILE = $(BIN)-$(VERSION).tar

dist:
	echo $(VERSION) >VERSION
	git archive --format=tar --prefix $(BIN)-$(VERSION)/ HEAD > $(TARFILE)
	rm -f VERSION
	gzip -f $(TARFILE)

.PHONY: snapshot
snapshot:
# brew install goreleaser/tap/goreleaser
	goreleaser release --snapshot --skip publish --clean

# Creates and runs S3 gateway instance in a docker container
.PHONY: up-posix
up-posix:
	$(DOCKERCOMPOSE) up posix

# Creates and runs S3 gateway proxy instance in a docker container
.PHONY: up-proxy
up-proxy:
	$(DOCKERCOMPOSE) up proxy

# Creates and runs S3 gateway to azurite instance in a docker container
.PHONY: up-azurite
up-azurite:
	$(DOCKERCOMPOSE) up azurite azuritegw

# Creates and runs both S3 gateway and proxy server instances in docker containers
.PHONY: up-app
up-app:
	$(DOCKERCOMPOSE) up

# Run the host-style tests in docker containers
.PHONY: test-host-style
test-host-style:
	@compose_file=tests/host-style-tests/docker-compose.yml; \
	COMPOSE_MENU=false docker compose -f "$$compose_file" down -v --remove-orphans >/dev/null 2>&1 || true; \
	COMPOSE_MENU=false docker compose -f "$$compose_file" up --build --abort-on-container-exit --exit-code-from test; \
	status=$$?; \
	COMPOSE_MENU=false docker compose -f "$$compose_file" down -v --remove-orphans; \
	exit $$status

# Run the static website hosting tests in docker containers
.PHONY: test-website-hosting
test-website-hosting:
	@compose_file=tests/website-hosting-tests/docker-compose.yml; \
	COMPOSE_MENU=false docker compose -f "$$compose_file" down -v --remove-orphans >/dev/null 2>&1 || true; \
	COMPOSE_MENU=false docker compose -f "$$compose_file" up --build --abort-on-container-exit --exit-code-from test; \
	status=$$?; \
	COMPOSE_MENU=false docker compose -f "$$compose_file" down -v --remove-orphans; \
	exit $$status
