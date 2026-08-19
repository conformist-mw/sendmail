package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These modes must work on a machine where the configuration file has not been
// filled in yet, so they are handled before the config is loaded.
func TestRunModesThatNeedNoConfig(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		wantCode int
		wantOut  string
	}{
		{"help", []string{"--help"}, exitOK, "Usage: sendmail"},
		{"version", []string{"--version"}, exitOK, "tg-sendmail"},
		{"mailq", []string{"-bp"}, exitOK, "Mail queue is empty"},
		{"daemon mode is a no-op", []string{"-bd"}, exitOK, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.argv, strings.NewReader(""), &stdout, &stderr)

			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tc.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.wantOut) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tc.wantOut)
			}
		})
	}
}

// withStubAPI points the client at a stub server and installs a config that
// makes run() take the normal delivery path.
func withStubAPI(t *testing.T, handler http.HandlerFunc) {
	t.Helper()

	server := httptest.NewServer(handler)
	originalURL, originalPaths := defaultBaseURL, configPaths
	defaultBaseURL = server.URL

	dir := t.TempDir()
	config := filepath.Join(dir, "sendmail.yaml")
	contents := "log:\n  level: debug\n  path: " + filepath.Join(dir, "test.log") +
		"\ntelegram:\n  bot_token: \"token\"\n  chat_id: \"42\"\n"
	if err := os.WriteFile(config, []byte(contents), 0600); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}
	configPaths = []string{config}

	t.Cleanup(func() {
		server.Close()
		defaultBaseURL, configPaths = originalURL, originalPaths
	})
}

func TestRunDeliversMail(t *testing.T) {
	var payload map[string]interface{}
	withStubAPI(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		io.WriteString(w, `{"ok":true,"result":{}}`)
	})

	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("Subject: cron failure\n\ncommand not found\n")
	code := run([]string{"-oi", "-FCron Daemon", "-froot@host", "user@host"}, stdin, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	text, _ := payload["text"].(string)
	for _, want := range []string{"cron failure", "command not found", "user@host", "Cron Daemon &lt;root@host&gt;"} {
		if !strings.Contains(text, want) {
			t.Errorf("sent text %q does not contain %q", text, want)
		}
	}
}

func TestRunFailsWhenTelegramRejectsTheMessage(t *testing.T) {
	withStubAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"ok":false,"description":"chat not found"}`)
	})

	var stdout, stderr bytes.Buffer
	code := run(nil, strings.NewReader("Subject: x\n\nbody\n"), &stdout, &stderr)

	if code != exitUnavailable {
		t.Errorf("exit code = %d, want %d", code, exitUnavailable)
	}
	if !strings.Contains(stderr.String(), "chat not found") {
		t.Errorf("stderr = %q, want the API error", stderr.String())
	}
}

func TestRunReportsMissingConfig(t *testing.T) {
	original := configPaths
	configPaths = []string{t.TempDir() + "/missing.yaml"}
	defer func() { configPaths = original }()

	var stdout, stderr bytes.Buffer
	code := run([]string{"user@host"}, strings.NewReader("Subject: x\n\nbody\n"), &stdout, &stderr)

	if code != exitConfig {
		t.Errorf("exit code = %d, want %d", code, exitConfig)
	}
	if !strings.Contains(stderr.String(), "configuration file") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
