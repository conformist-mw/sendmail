package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// tgMaxTextLength is the Telegram limit for a text message.
	tgMaxTextLength = 4096
	// previewRunes is how much of a too-long message is shown inline.
	previewRunes = 500
	// httpTimeout keeps a stalled API call from hanging a cron job forever.
	httpTimeout = 30 * time.Second

	longMessageName = "long_message.txt"
)

// defaultBaseURL is a variable so that tests can point the client elsewhere.
var defaultBaseURL = "https://api.telegram.org"

// apiError is a failure reported by Telegram itself, as opposed to a transport
// failure.
type apiError struct {
	Method      string
	Status      int
	Description string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s: status %d: %s", e.Method, e.Status, e.Description)
}

type Telegram struct {
	token   string
	chatID  string
	client  *http.Client
	log     *Logger
	baseURL string // overridden in tests
}

func newTelegram(cfg Config, logger *Logger) *Telegram {
	return &Telegram{
		token:  cfg.Telegram.BotToken,
		chatID: cfg.Telegram.ChatID,
		client: &http.Client{Timeout: httpTimeout},
		log:    logger,
	}
}

func (t *Telegram) url(method string) string {
	base := t.baseURL
	if base == "" {
		base = defaultBaseURL
	}
	return fmt.Sprintf("%s/bot%s/%s", base, t.token, method)
}

// redact keeps the bot token out of logs and error messages: the log file is
// world-readable so that any user can send mail through it.
func (t *Telegram) redact(s string) string {
	if t.token == "" {
		return s
	}
	return strings.ReplaceAll(s, t.token, "<token>")
}

// call performs the request and turns both transport and API-level failures
// into errors, so that a rejected message is never reported as delivered.
func (t *Telegram) call(method string, req *http.Request) ([]byte, error) {
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", method, t.redact(err.Error()))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read response: %s", method, t.redact(err.Error()))
	}
	t.log.Debugf("%s response: %s", method, body)

	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("%s: status %d, unparsable response: %s",
			method, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if !result.OK || resp.StatusCode != http.StatusOK {
		return nil, &apiError{Method: method, Status: resp.StatusCode, Description: result.Description}
	}
	return body, nil
}

func (t *Telegram) postJSON(method string, payload map[string]interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	t.log.Debugf("%s payload: %s", method, data)

	req, err := http.NewRequest(http.MethodPost, t.url(method), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	_, err = t.call(method, req)
	return err
}

// Send delivers the notification, falling back to an attachment when the
// message does not fit into a single Telegram message.
func (t *Telegram) Send(plain, htmlText string) error {
	if utf8.RuneCountInString(htmlText) <= tgMaxTextLength {
		return t.SendMessage(htmlText)
	}
	// The preview is cut from the plain text and escaped afterwards: cutting
	// the HTML itself would split a tag or an entity and Telegram would then
	// reject the whole message.
	t.log.Infof("message is %d characters, sending a preview and the full text as %s",
		utf8.RuneCountInString(htmlText), longMessageName)
	preview := html.EscapeString(truncateRunes(plain, previewRunes)) +
		"\n\n<b>Message is too long. See attached file below</b>"
	if err := t.SendMessage(preview); err != nil {
		return err
	}
	return t.SendDocument(longMessageName, []byte(plain))
}

func (t *Telegram) SendMessage(text string) error {
	return t.postJSON("sendMessage", map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "HTML",
	})
}

func (t *Telegram) SendDocument(name string, content []byte) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	if err := writer.WriteField("chat_id", t.chatID); err != nil {
		return err
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(
		`form-data; name="document"; filename="%s"`, escapeQuotes(filepath.Base(name))))
	header.Set("Content-Type", contentType(name))
	part, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	if _, err := part.Write(content); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, t.url("sendDocument"), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	_, err = t.call("sendDocument", req)
	return err
}

// Chat identifies a conversation the bot has seen.
type Chat struct {
	ID       int64
	Username string
}

// GetUpdates reports the chats that have messaged the bot, which is how a user
// discovers the chat_id to configure.
func (t *Telegram) GetUpdates() ([]Chat, error) {
	req, err := http.NewRequest(http.MethodGet, t.url("getUpdates"), nil)
	if err != nil {
		return nil, err
	}
	body, err := t.call("getUpdates", req)
	if err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
			return nil, fmt.Errorf("%w; this usually means a webhook is registered "+
				"for the bot, and Telegram refuses getUpdates while one is active", err)
		}
		return nil, err
	}

	var result struct {
		Result []struct {
			Message struct {
				Chat struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("getUpdates: cannot decode response: %w", err)
	}

	chats := make([]Chat, 0, len(result.Result))
	for _, update := range result.Result {
		chats = append(chats, Chat{
			ID:       update.Message.Chat.ID,
			Username: update.Message.Chat.Username,
		})
	}
	return chats, nil
}

// truncateRunes cuts on a rune boundary so the result stays valid UTF-8.
func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// textExtensions covers the files this tool actually sends. A minimal system
// carries no MIME database for mime.TypeByExtension to consult, and a log
// would then be announced as an opaque blob.
var textExtensions = map[string]bool{
	".txt": true, ".log": true, ".conf": true, ".cfg": true,
	".ini": true, ".yaml": true, ".yml": true, ".md": true,
}

func contentType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if textExtensions[ext] {
		return "text/plain; charset=utf-8"
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

func escapeQuotes(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}
