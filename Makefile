.PHONY: build build-all test lint clean

GO_LDFLAGS = -s -w

build:
	go build -trimpath -ldflags="$(GO_LDFLAGS)" -o sendmail .

build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(GO_LDFLAGS)" -o sendmail-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(GO_LDFLAGS)" -o sendmail-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="$(GO_LDFLAGS)" -o sendmail-linux-armv7 .

test:
	go test ./...

lint:
	test -z "$$(gofmt -l *.go)" || (gofmt -l *.go && exit 1)
	go vet ./...

clean:
	rm -rf sendmail sendmail-linux-* .gocache
