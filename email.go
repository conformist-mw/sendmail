package main

import (
	"fmt"
	"html"
	"io"
	"net/mail"
	"strings"
)

// Header is a single message header. Headers are kept as an ordered slice so
// that the notification shows them in the order the sender wrote them.
type Header struct {
	Key   string
	Value string
}

type Message struct {
	Headers []Header
	Body    string
}

// Get returns the first value of a header, matched case-insensitively.
func (m *Message) Get(key string) string {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Key, key) {
			return h.Value
		}
	}
	return ""
}

func (m *Message) Add(key, value string) {
	m.Headers = append(m.Headers, Header{Key: key, Value: value})
}

// ParseMessage reads a message the way an MTA has to: leniently. Input that
// does not start with headers is a body, and a malformed line ends the header
// block instead of rejecting the message.
func ParseMessage(r io.Reader) (*Message, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	text := string(raw)
	msg := &Message{}

	for pos := 0; pos < len(text); {
		line, next := readLine(text, pos)

		if line == "" {
			msg.Body = text[next:]
			return msg, nil
		}
		if (line[0] == ' ' || line[0] == '\t') && len(msg.Headers) > 0 {
			last := &msg.Headers[len(msg.Headers)-1]
			last.Value = strings.TrimSpace(last.Value + " " + strings.TrimSpace(line))
			pos = next
			continue
		}

		key, value, ok := splitHeader(line)
		if !ok {
			msg.Body = text[pos:]
			return msg, nil
		}
		msg.Add(key, value)
		pos = next
	}

	return msg, nil
}

// readLine returns the line starting at pos without its terminator, plus the
// offset of the next line.
func readLine(text string, pos int) (line string, next int) {
	end := strings.IndexByte(text[pos:], '\n')
	if end < 0 {
		return strings.TrimSuffix(text[pos:], "\r"), len(text)
	}
	return strings.TrimSuffix(text[pos:pos+end], "\r"), pos + end + 1
}

// splitHeader splits "Name: value", requiring a name of printable characters
// as defined by RFC 5322 field names.
func splitHeader(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	for j := 0; j < i; j++ {
		if line[j] < '!' || line[j] > '~' {
			return "", "", false
		}
	}
	return line[:i], strings.TrimSpace(line[i+1:]), true
}

func generateFullName(fullName, address string) string {
	if fullName != "" {
		return fmt.Sprintf("%s <%s>", fullName, address)
	}
	return address
}

// applyDefaults fills in the headers a submitting program left to the MTA.
func applyDefaults(msg *Message, opts *Options) {
	if !opts.ReadRecipients && msg.Get("To") == "" {
		for _, arg := range opts.Recipients {
			// RFC 822 section 6: the address does not have to be valid, so
			// whatever was given goes into To: unchanged when parsing fails.
			if addr, err := mail.ParseAddress(arg); err == nil {
				msg.Add("To", generateFullName(addr.Name, addr.Address))
			} else {
				msg.Add("To", arg)
			}
		}
	}
	if msg.Get("From") == "" && opts.SenderAddress != "" {
		msg.Add("From", generateFullName(opts.SenderName, opts.SenderAddress))
	}
}

// renderText is the plain form, used for the attachment of long messages.
func renderText(msg *Message, node string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Node: %s\n\n", node)
	for _, h := range msg.Headers {
		fmt.Fprintf(&b, "%s: %s\n", h.Key, h.Value)
	}
	b.WriteString("\n")
	b.WriteString(msg.Body)
	return b.String()
}

// renderHTML is the form sent to Telegram with parse_mode=HTML.
func renderHTML(msg *Message, node string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Node: <b>%s</b>\n\n", html.EscapeString(node))
	for _, h := range msg.Headers {
		fmt.Fprintf(&b, "<i>%s:</i> <b>%s</b>\n",
			html.EscapeString(h.Key), html.EscapeString(h.Value))
	}
	b.WriteString("\n")
	b.WriteString("<pre>" + html.EscapeString(msg.Body) + "</pre>")
	return b.String()
}
