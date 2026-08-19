// Command sendmail is a drop-in replacement for the MTA sendmail binary that
// delivers messages to a Telegram chat instead of over SMTP.
package main

import (
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

// version is replaced at build time with the package version.
var version = "dev"

// Exit codes follow sysexits.h, which is what callers of an MTA expect.
const (
	exitOK          = 0
	exitUsage       = 64
	exitNoInput     = 66
	exitUnavailable = 69
	exitConfig      = 78
)

const usage = `Usage: sendmail [options] [recipient ...]

Drop-in replacement for the MTA sendmail binary that delivers mail to a
Telegram chat. The message is read from standard input.

Options:
  -f address     envelope sender address (also -r)
  -F name        full name of the sender
  -t             read recipients from the message headers
  -i, -oi        accepted for compatibility, no effect
  --send-file F  send a local file to the chat
  --get-updates  print the chat ids that have messaged the bot
  --help         show this help
  --version      show the version

Other standard sendmail options are accepted and ignored.

Configuration is read from the first of: sendmail.yaml,
/etc/tg-sendmail.yaml, /etc/sendmail.yaml
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts := ParseArgs(argv)

	if opts.Help {
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	if opts.Version {
		fmt.Fprintf(stdout, "tg-sendmail %s\n", version)
		return exitOK
	}
	// Queue and daemon modes have nothing to act on here, but callers such as
	// mailq must not see a failure.
	switch opts.Mode {
	case "p":
		fmt.Fprintln(stdout, "Mail queue is empty")
		return exitOK
	case "d", "D", "v":
		return exitOK
	}

	cfg, err := loadConfig(configPaths)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitConfig
	}

	logWriter, closeLog, err := openLogWriter(cfg.Log.Path)
	defer closeLog()
	logger := newLogger(logWriter, cfg.Log.Level)
	if err != nil {
		logger.Warnf("cannot open log file, logging to stderr: %v", err)
	}

	telegram := newTelegram(cfg, logger)

	switch {
	case opts.GetUpdates:
		return getUpdates(telegram, cfg, logger, stdout, stderr)
	case opts.SendFile != "":
		return sendFile(telegram, cfg, logger, opts.SendFile, stderr)
	default:
		return sendMail(telegram, cfg, logger, opts, stdin, stderr)
	}
}

func getUpdates(telegram *Telegram, cfg Config, logger *Logger, stdout, stderr io.Writer) int {
	if cfg.Telegram.BotToken == "" {
		return configError(logger, stderr, "bot_token is not set")
	}

	chats, err := telegram.GetUpdates()
	if err != nil {
		logger.Errorf("%v", err)
		fmt.Fprintln(stderr, err)
		return exitUnavailable
	}
	if len(chats) == 0 {
		const message = "No updates. Try to send some messages to the bot"
		logger.Warnf("%s", message)
		fmt.Fprintln(stdout, message)
		return exitOK
	}
	for _, chat := range chats {
		line := fmt.Sprintf("Chat Id: %d. Username: %s", chat.ID, chat.Username)
		logger.Infof("get updates data: %s", line)
		fmt.Fprintln(stdout, line)
	}
	return exitOK
}

func sendFile(telegram *Telegram, cfg Config, logger *Logger, path string, stderr io.Writer) int {
	content, err := os.ReadFile(path)
	if err != nil {
		logger.Errorf("cannot read %s: %v", path, err)
		fmt.Fprintf(stderr, "cannot read %s: %v\n", path, err)
		return exitNoInput
	}
	if !cfg.HasCredentials() {
		return configError(logger, stderr, "")
	}
	if err := telegram.SendDocument(path, content); err != nil {
		logger.Errorf("%v", err)
		fmt.Fprintln(stderr, err)
		return exitUnavailable
	}
	logger.Infof("sent %s (%d bytes) to chat %s", path, len(content), cfg.Telegram.ChatID)
	return exitOK
}

func sendMail(telegram *Telegram, cfg Config, logger *Logger, opts *Options, stdin io.Reader, stderr io.Writer) int {
	msg, err := ParseMessage(stdin)
	if err != nil {
		logger.Errorf("cannot read message: %v", err)
		fmt.Fprintf(stderr, "cannot read message: %v\n", err)
		return exitNoInput
	}
	applyDefaults(msg, opts)
	logger.Debugf("prepared email headers: %v", msg.Headers)

	node := hostname()
	plain, htmlText := renderText(msg, node), renderHTML(msg, node)
	logger.Debugf("prepared message: %s", htmlText)

	if !cfg.HasCredentials() {
		return configError(logger, stderr, "")
	}
	if err := telegram.Send(plain, htmlText); err != nil {
		logger.Errorf("%v", err)
		fmt.Fprintln(stderr, err)
		return exitUnavailable
	}
	// A delivery that logs nothing leaves no way to tell a working install from
	// one that is never invoked, so this line is emitted at info level.
	logger.Infof("delivered to chat %s: subject %q, %d characters",
		cfg.Telegram.ChatID, msg.Get("Subject"), utf8.RuneCountInString(htmlText))
	return exitOK
}

func configError(logger *Logger, stderr io.Writer, reason string) int {
	message := "Please fill /etc/tg-sendmail.yaml configuration file!"
	if reason != "" {
		message = fmt.Sprintf("%s (%s)", message, reason)
	}
	logger.Errorf("%s", message)
	fmt.Fprintln(stderr, message)
	return exitConfig
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}
