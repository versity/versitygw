FROM golang:1.20-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY ./ ./

WORKDIR /app/cmd/versitygw
RUN go build -o versitygw

FROM alpine:latest

# These arguments can be overriden when building the image
ARG IAM_DIR=/tmp/vgw
ARG SETUP_DIR=/tmp/vgw

RUN mkdir -p $IAM_DIR
RUN mkdir -p $SETUP_DIR

COPY --from=0 /app/cmd/versitygw/versitygw /app/versitygw

ENTRYPOINT [ "/app/versitygw" ]