.PHONY: build build-all clean

build:
	go build -ldflags="-s -w" -o sendmail sendmail.go

build-all:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o sendmail-linux-amd64 sendmail.go
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o sendmail-linux-arm64 sendmail.go
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o sendmail-linux-armv7 sendmail.go

clean:
	rm -f sendmail sendmail-linux-*
