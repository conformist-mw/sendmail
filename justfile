# Build the binary for current platform
build:
    go build -trimpath -ldflags="-s -w" -o sendmail .

# Build binaries for all platforms
build-all:
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sendmail-linux-amd64 .
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o sendmail-linux-arm64 .
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="-s -w" -o sendmail-linux-armv7 .

# Run the tests
test:
    go test ./...

# Check formatting and run go vet
lint:
    test -z "$(gofmt -l *.go)" || (gofmt -l *.go && exit 1)
    go vet ./...

# Build the debian package
package:
    debuild --no-lintian

# Clean build artifacts
clean:
    rm -rf sendmail sendmail-linux-* .gocache

# Get Telegram chat ID (send a message to your bot first)
get-chat-id:
    ./sendmail --get-updates

# Send a test file to Telegram
send-file FILE:
    ./sendmail --send-file {{FILE}}

# Send a test email via stdin
send-email:
    @printf 'Subject: Test Email\nFrom: test@example.com\nTo: recipient@example.com\n\nThis is a test email body.\n' | ./sendmail

# Send a custom email with specific sender
send-email-custom SUBJECT BODY:
    @printf 'Subject: {{SUBJECT}}\n\n{{BODY}}\n' | ./sendmail -f sender@example.com

# Show help
help:
    @just --list
