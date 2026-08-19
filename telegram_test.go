package main

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// newTestTelegram wires a client against a stub API server.
func newTestTelegram(t *testing.T, handler http.HandlerFunc) (*Telegram, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	telegram := &Telegram{
		token:   "secret-token",
		chatID:  "42",
		client:  server.Client(),
		log:     newLogger(io.Discard, "debug"),
		baseURL: server.URL,
	}
	return telegram, server.Close
}

func TestSendMessageReportsAPIFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"bad request", http.StatusBadRequest, `{"ok":false,"description":"chat not found"}`},
		{"unauthorized", http.StatusUnauthorized, `{"ok":false,"description":"Unauthorized"}`},
		{"ok false with 200", http.StatusOK, `{"ok":false,"description":"nope"}`},
		{"unparsable body", http.StatusBadGateway, `<html>gateway</html>`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			telegram, closeServer := newTestTelegram(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			defer closeServer()

			if err := telegram.SendMessage("hello"); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestSendMessageSucceeds(t *testing.T) {
	var payload map[string]interface{}
	telegram, closeServer := newTestTelegram(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
		io.WriteString(w, `{"ok":true}`)
	})
	defer closeServer()

	if err := telegram.SendMessage("hello"); err != nil {
		t.Fatalf("SendMessage returned %v", err)
	}
	if payload["chat_id"] != "42" || payload["text"] != "hello" || payload["parse_mode"] != "HTML" {
		t.Errorf("payload = %+v", payload)
	}
}

func TestSendSplitsLongMessages(t *testing.T) {
	// A Cyrillic body is over the byte limit long before it is over the rune
	// limit, which is what the message length has to be measured in.
	body := strings.Repeat("привет ", 900)
	msg := &Message{Headers: []Header{{"Subject", "тест"}}, Body: body}
	plain, htmlText := renderText(msg, "узел"), renderHTML(msg, "узел")

	var sentText string
	var document []byte
	var documentName string

	telegram, closeServer := newTestTelegram(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "sendMessage") {
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			sentText, _ = payload["text"].(string)
		} else {
			_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				t.Errorf("bad content type: %v", err)
			}
			reader := multipart.NewReader(r.Body, params["boundary"])
			form, err := reader.ReadForm(1 << 20)
			if err != nil {
				t.Fatalf("cannot parse multipart form: %v", err)
			}
			file := form.File["document"][0]
			documentName = file.Filename
			opened, _ := file.Open()
			document, _ = io.ReadAll(opened)
		}
		io.WriteString(w, `{"ok":true}`)
	})
	defer closeServer()

	if err := telegram.Send(plain, htmlText); err != nil {
		t.Fatalf("Send returned %v", err)
	}

	if !utf8.ValidString(sentText) {
		t.Error("preview is not valid UTF-8")
	}
	if utf8.RuneCountInString(sentText) > tgMaxTextLength {
		t.Errorf("preview is %d runes, over the limit", utf8.RuneCountInString(sentText))
	}
	if !strings.Contains(sentText, "Message is too long") {
		t.Errorf("preview lacks the notice: %q", sentText)
	}
	if documentName != longMessageName {
		t.Errorf("document name = %q, want %q", documentName, longMessageName)
	}
	if string(document) != plain {
		t.Error("attached document does not carry the full message")
	}
}

func TestSendKeepsShortMessagesInline(t *testing.T) {
	var calls []string
	telegram, closeServer := newTestTelegram(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:])
		io.WriteString(w, `{"ok":true}`)
	})
	defer closeServer()

	if err := telegram.Send("plain", "<pre>plain</pre>"); err != nil {
		t.Fatalf("Send returned %v", err)
	}
	if len(calls) != 1 || calls[0] != "sendMessage" {
		t.Errorf("calls = %v, want a single sendMessage", calls)
	}
}

func TestGetUpdates(t *testing.T) {
	telegram, closeServer := newTestTelegram(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true,"result":[{"message":{"chat":{"id":42,"username":"user"}}}]}`)
	})
	defer closeServer()

	chats, err := telegram.GetUpdates()
	if err != nil {
		t.Fatalf("GetUpdates returned %v", err)
	}
	if len(chats) != 1 || chats[0].ID != 42 || chats[0].Username != "user" {
		t.Errorf("chats = %+v", chats)
	}
}

func TestErrorsDoNotLeakTheToken(t *testing.T) {
	telegram := &Telegram{
		token:   "secret-token",
		client:  &http.Client{},
		log:     newLogger(io.Discard, "debug"),
		baseURL: "http://127.0.0.1:1", // nothing listens here
	}

	err := telegram.SendMessage("hello")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error leaks the bot token: %v", err)
	}
}

func TestTruncateRunes(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"привет", 3, "при"},
		{"привет", 100, "привет"},
		{"abc", 0, ""},
		{"", 5, ""},
	}
	for _, tc := range tests {
		if got := truncateRunes(tc.in, tc.n); got != tc.want {
			t.Errorf("truncateRunes(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestContentType(t *testing.T) {
	if got := contentType("/var/log/syslog.txt"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("contentType(.txt) = %q, want text/plain", got)
	}
	if got := contentType("/var/log/tg-sendmail.unknownext"); got != "application/octet-stream" {
		t.Errorf("contentType(unknown) = %q", got)
	}
}

// A registered webhook makes getUpdates fail with 409 for the whole bot, which
// is what both live hosts return. The bare status is not actionable.
func TestGetUpdatesExplainsConflict(t *testing.T) {
	telegram, closeServer := newTestTelegram(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"ok":false,"description":"Conflict: can't use getUpdates method while webhook is active"}`)
	})
	defer closeServer()

	_, err := telegram.GetUpdates()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "webhook") {
		t.Errorf("error does not mention the webhook cause: %v", err)
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Errorf("error does not carry the status code: %v", err)
	}
}
