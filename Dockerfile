FROM golang:latest
RUN go get -u github.com/golang/dep/...
RUN apt-get update -qqy && \
apt-get install -qqy sudo aptitude jq zip
