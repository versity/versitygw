FROM golang:1.20-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY ./ ./

WORKDIR /app/cmd/versitygw
RUN go build -o versitygw

FROM alpine:latest

RUN mkdir /tmp/vgw

COPY --from=0 /app/cmd/versitygw/versitygw /app/versitygw

ENTRYPOINT [ "/app/versitygw" ]