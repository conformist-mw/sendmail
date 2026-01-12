# Build the binary for current platform
build:
    go build -ldflags="-s -w" -o sendmail sendmail.go

# Build binaries for all platforms
build-all:
    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o sendmail-linux-amd64 sendmail.go
    GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o sendmail-linux-arm64 sendmail.go
    GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o sendmail-linux-armv7 sendmail.go

# Clean build artifacts
clean:
    rm -f sendmail sendmail-linux-*

# Get Telegram chat ID (send a message to your bot first)
get-chat-id:
    ./sendmail -get-updates

# Send a test file to Telegram
send-file FILE:
    ./sendmail -send-file {{FILE}}

# Send a test email via stdin
send-email:
    @echo -e "Subject: Test Email\nFrom: test@example.com\nTo: recipient@example.com\n\nThis is a test email body." | ./sendmail

# Send a custom email with specific sender
send-email-custom SUBJECT BODY:
    @echo -e "Subject: {{SUBJECT}}\n\n{{BODY}}" | ./sendmail -f sender@example.com

# Run the program (reads email from stdin)
run:
    ./sendmail

# Show help
help:
    @just --list
