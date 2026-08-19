package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	valid := writeFile(t, dir, "valid.yaml", `
log:
  level: debug
  path: /var/log/tg-sendmail.log
telegram:
  bot_token: "token"
  chat_id: "42"
`)
	broken := writeFile(t, dir, "broken.yaml", "log: [unclosed\n")
	missing := filepath.Join(dir, "missing.yaml")

	t.Run("first readable file wins", func(t *testing.T) {
		cfg, err := loadConfig([]string{missing, valid})
		if err != nil {
			t.Fatalf("loadConfig returned %v", err)
		}
		if cfg.Telegram.BotToken != "token" || cfg.Telegram.ChatID != "42" {
			t.Errorf("telegram config = %+v", cfg.Telegram)
		}
		if cfg.Log.Level != "debug" || cfg.Log.Path != "/var/log/tg-sendmail.log" {
			t.Errorf("log config = %+v", cfg.Log)
		}
		if !cfg.HasCredentials() {
			t.Error("HasCredentials = false")
		}
	})

	t.Run("no config found", func(t *testing.T) {
		if _, err := loadConfig([]string{missing}); !errors.Is(err, errNoConfig) {
			t.Errorf("err = %v, want errNoConfig", err)
		}
	})

	t.Run("malformed yaml is reported", func(t *testing.T) {
		_, err := loadConfig([]string{broken, valid})
		if err == nil {
			t.Fatal("expected a parse error")
		}
		if errors.Is(err, errNoConfig) {
			t.Error("parse error was reported as a missing file")
		}
	})
}

func TestHasCredentials(t *testing.T) {
	var cfg Config
	if cfg.HasCredentials() {
		t.Error("empty config reported as configured")
	}
	cfg.Telegram.BotToken = "token"
	if cfg.HasCredentials() {
		t.Error("config without chat_id reported as configured")
	}
}

func TestParseLevel(t *testing.T) {
	tests := map[string]logLevel{
		"debug": levelDebug, "DEBUG": levelDebug, " info ": levelInfo,
		"warning": levelWarn, "error": levelError, "": levelInfo, "nonsense": levelInfo,
	}
	for in, want := range tests {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLoggerRespectsLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	writer, closeLog, err := openLogWriter(path)
	if err != nil {
		t.Fatalf("openLogWriter returned %v", err)
	}
	defer closeLog()

	logger := newLogger(writer, "warn")
	logger.Debugf("debug message")
	logger.Errorf("error message")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read log: %v", err)
	}
	if string(content) == "" {
		t.Fatal("nothing was logged")
	}
	if got := string(content); strings.Contains(got, "debug message") {
		t.Errorf("debug message was logged at warn level: %q", got)
	}
	if got := string(content); !strings.Contains(got, "error message") {
		t.Errorf("error message is missing: %q", got)
	}
}

func TestOpenLogWriterFallsBackToStderr(t *testing.T) {
	writer, closeLog, err := openLogWriter("/nonexistent-dir/tg-sendmail.log")
	defer closeLog()
	if err == nil {
		t.Error("expected an error for an unwritable path")
	}
	if writer != os.Stderr {
		t.Error("writer is not stderr")
	}

	writer, closeLog2, err := openLogWriter("")
	defer closeLog2()
	if err != nil || writer != os.Stderr {
		t.Errorf("empty path: writer = %v, err = %v", writer, err)
	}
}

// The deployed INI hosts hit an HTTP 404 because the quotes around the value
// were kept and travelled into the request URL.
func TestLoadConfigCleansCredentials(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "quoted.yaml", "telegram:\n  bot_token: '\"123456:ABC-DEF\"'\n  chat_id: \" 42 \"\n")

	cfg, err := loadConfig([]string{path})
	if err != nil {
		t.Fatalf("loadConfig returned %v", err)
	}
	if cfg.Telegram.BotToken != "123456:ABC-DEF" {
		t.Errorf("bot_token = %q, want the quotes stripped", cfg.Telegram.BotToken)
	}
	if cfg.Telegram.ChatID != "42" {
		t.Errorf("chat_id = %q, want the spaces stripped", cfg.Telegram.ChatID)
	}
}
