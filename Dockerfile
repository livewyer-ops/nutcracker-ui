FROM golang:1.6

ENV GOPATH /go

VOLUME deploy /output

COPY . /go/src/github.com/nutmegdevelopment/nutcracker-ui

RUN cd /go/src/github.com/nutmegdevelopment/nutcracker-ui && go get -d

RUN cd /go/src/github.com/nutmegdevelopment/nutcracker-ui && go build -o /output/nutcracker-ui