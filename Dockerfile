FROM golang:alpine as builder

LABEL maintainer="Lars Roman Krieger <email@lars-krieger.de>"

RUN apk update && apk add --no-cache git

COPY . $GOPATH/src/lars-krieger.de/pseudo-kms/
WORKDIR $GOPATH/src/lars-krieger.de/pseudo-kms/

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN cd main && CGO_ENABLED=0 go build -o /usr/bin/pseudo-kms main.go

EXPOSE 80

ENTRYPOINT ["/usr/bin/pseudo-kms"]
