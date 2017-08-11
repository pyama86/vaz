FROM golang:latest
RUN go get -u github.com/golang/dep/...
RUN apt-get -qqy &&
apt-get install -qqy sudo
