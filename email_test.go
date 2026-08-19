package main

import (
	"strings"
	"testing"
)

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantHeaders []Header
		wantBody    string
	}{
		{
			name:  "headers and body",
			input: "Subject: test\nFrom: root@host\n\nbody line\n",
			wantHeaders: []Header{
				{"Subject", "test"},
				{"From", "root@host"},
			},
			wantBody: "body line\n",
		},
		{
			name:        "body without headers is not an error",
			input:       "just a body line\n",
			wantHeaders: nil,
			wantBody:    "just a body line\n",
		},
		{
			name:        "malformed line ends the header block",
			input:       "Subject: test\ngarbage line\nmore body\n",
			wantHeaders: []Header{{"Subject", "test"}},
			wantBody:    "garbage line\nmore body\n",
		},
		{
			name:        "folded headers are unfolded",
			input:       "Subject: a very\n long subject\n\tcontinued\n\nbody\n",
			wantHeaders: []Header{{"Subject", "a very long subject continued"}},
			wantBody:    "body\n",
		},
		{
			name:        "crlf line endings",
			input:       "Subject: test\r\n\r\nbody\r\n",
			wantHeaders: []Header{{"Subject", "test"}},
			wantBody:    "body\r\n",
		},
		{
			name:        "headers without a body",
			input:       "Subject: test\n",
			wantHeaders: []Header{{"Subject", "test"}},
			wantBody:    "",
		},
		{
			name:        "empty input",
			input:       "",
			wantHeaders: nil,
			wantBody:    "",
		},
		{
			name:        "leading blank line means everything is body",
			input:       "\nSubject: not a header\n",
			wantHeaders: nil,
			wantBody:    "Subject: not a header\n",
		},
		{
			name:        "colon in the value is kept",
			input:       "Subject: 12:30 report\n\nbody",
			wantHeaders: []Header{{"Subject", "12:30 report"}},
			wantBody:    "body",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := ParseMessage(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("ParseMessage returned error: %v", err)
			}
			if len(msg.Headers) != len(tc.wantHeaders) {
				t.Fatalf("headers = %+v, want %+v", msg.Headers, tc.wantHeaders)
			}
			for i, want := range tc.wantHeaders {
				if msg.Headers[i] != want {
					t.Errorf("header %d = %+v, want %+v", i, msg.Headers[i], want)
				}
			}
			if msg.Body != tc.wantBody {
				t.Errorf("body = %q, want %q", msg.Body, tc.wantBody)
			}
		})
	}
}

func TestMessageGetIsCaseInsensitive(t *testing.T) {
	msg := &Message{Headers: []Header{{"SUBJECT", "test"}}}
	if got := msg.Get("subject"); got != "test" {
		t.Errorf("Get(subject) = %q, want %q", got, "test")
	}
	if got := msg.Get("missing"); got != "" {
		t.Errorf("Get(missing) = %q, want empty", got)
	}
}

func TestApplyDefaults(t *testing.T) {
	t.Run("recipients become the To header", func(t *testing.T) {
		msg := &Message{}
		applyDefaults(msg, &Options{Recipients: []string{"User <user@host>", "second@host"}})
		if got := msg.Get("To"); got != "User <user@host>" {
			t.Errorf("To = %q", got)
		}
		if len(msg.Headers) != 2 {
			t.Errorf("headers = %+v, want two To headers", msg.Headers)
		}
	})

	t.Run("invalid address is kept verbatim", func(t *testing.T) {
		msg := &Message{}
		applyDefaults(msg, &Options{Recipients: []string{"not an address"}})
		if got := msg.Get("To"); got != "not an address" {
			t.Errorf("To = %q", got)
		}
	})

	t.Run("-t leaves recipients out of the headers", func(t *testing.T) {
		msg := &Message{}
		applyDefaults(msg, &Options{ReadRecipients: true, Recipients: []string{"user@host"}})
		if got := msg.Get("To"); got != "" {
			t.Errorf("To = %q, want empty", got)
		}
	})

	t.Run("existing To header is not touched", func(t *testing.T) {
		msg := &Message{Headers: []Header{{"To", "original@host"}}}
		applyDefaults(msg, &Options{Recipients: []string{"user@host"}})
		if len(msg.Headers) != 1 {
			t.Errorf("headers = %+v, want unchanged", msg.Headers)
		}
	})

	t.Run("sender fills an empty From header", func(t *testing.T) {
		msg := &Message{}
		applyDefaults(msg, &Options{SenderName: "Cron", SenderAddress: "root@host"})
		if got := msg.Get("From"); got != "Cron <root@host>" {
			t.Errorf("From = %q", got)
		}
	})
}

func TestRenderPreservesHeaderOrder(t *testing.T) {
	msg := &Message{
		Headers: []Header{{"Subject", "a"}, {"From", "b"}, {"To", "c"}},
		Body:    "body",
	}

	gotHTML := renderHTML(msg, "node")
	wantHTML := "Node: <b>node</b>\n\n" +
		"<i>Subject:</i> <b>a</b>\n<i>From:</i> <b>b</b>\n<i>To:</i> <b>c</b>\n" +
		"\n<pre>body</pre>"
	if gotHTML != wantHTML {
		t.Errorf("renderHTML =\n%q\nwant\n%q", gotHTML, wantHTML)
	}

	gotText := renderText(msg, "node")
	wantText := "Node: node\n\nSubject: a\nFrom: b\nTo: c\n\nbody"
	if gotText != wantText {
		t.Errorf("renderText =\n%q\nwant\n%q", gotText, wantText)
	}
}

func TestRenderHTMLEscapes(t *testing.T) {
	msg := &Message{Headers: []Header{{"Subject", "<b>bold</b>"}}, Body: "a & b <tag>"}
	got := renderHTML(msg, "node")
	if strings.Contains(got, "<b>bold</b>") {
		t.Errorf("header value was not escaped: %q", got)
	}
	if !strings.Contains(got, "a &amp; b &lt;tag&gt;") {
		t.Errorf("body was not escaped: %q", got)
	}
}
