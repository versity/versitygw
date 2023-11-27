FROM golang:1.20-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY ./ ./

WORKDIR /app/cmd/versitygw
RUN go build -o versitygw

RUN mkdir /tmp/vgw

ENTRYPOINT [ "./versitygw" ]