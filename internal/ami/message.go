package ami

import (
	"bytes"
	"strconv"
	"strings"
)

// Message is a single AMI packet: an ordered list of "Key: Value" headers.
//
// Order matters on the wire for a few actions (Originate's repeated Variable
// headers), and AMI header names are case-insensitive, so lookups fold case
// while the original spelling is preserved for sending.
type Message struct {
	keys []string
	vals []string
}

// NewMessage builds a message from alternating key/value arguments.
func NewMessage(kv ...string) *Message {
	m := &Message{}
	for i := 0; i+1 < len(kv); i += 2 {
		m.Add(kv[i], kv[i+1])
	}
	return m
}

// Add appends a header, allowing duplicates (Variable, ChanVariable, ...).
func (m *Message) Add(k, v string) {
	m.keys = append(m.keys, k)
	m.vals = append(m.vals, v)
}

// Set replaces the first occurrence of k, or appends it.
func (m *Message) Set(k, v string) {
	for i, key := range m.keys {
		if strings.EqualFold(key, k) {
			m.vals[i] = v
			return
		}
	}
	m.Add(k, v)
}

// Get returns the first value for k, or "".
func (m *Message) Get(k string) string {
	if m == nil {
		return ""
	}
	for i, key := range m.keys {
		if strings.EqualFold(key, k) {
			return m.vals[i]
		}
	}
	return ""
}

// GetInt parses the first value for k, returning def when absent or invalid.
func (m *Message) GetInt(k string, def int) int {
	v := strings.TrimSpace(m.Get(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// Values returns every value for k.
func (m *Message) Values(k string) []string {
	var out []string
	for i, key := range m.keys {
		if strings.EqualFold(key, k) {
			out = append(out, m.vals[i])
		}
	}
	return out
}

func (m *Message) Event() string    { return m.Get("Event") }
func (m *Message) Response() string { return m.Get("Response") }
func (m *Message) ActionID() string { return m.Get("ActionID") }

// Success reports whether a response packet indicates success.
func (m *Message) Success() bool {
	r := m.Response()
	return strings.EqualFold(r, "Success") || strings.EqualFold(r, "Follows")
}

// Bytes serialises the message including the terminating blank line.
func (m *Message) Bytes() []byte {
	var b bytes.Buffer
	for i, k := range m.keys {
		b.WriteString(k)
		b.WriteString(": ")
		// A newline inside a value would inject headers; AMI has no escaping,
		// so strip them.
		b.WriteString(strings.NewReplacer("\r", "", "\n", "").Replace(m.vals[i]))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// Redacted renders the message for logging with credentials removed.
func (m *Message) Redacted() string {
	var b strings.Builder
	for i, k := range m.keys {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(k)
		b.WriteString("=")
		if strings.EqualFold(k, "Secret") || strings.EqualFold(k, "Password") {
			b.WriteString("***")
		} else {
			b.WriteString(m.vals[i])
		}
	}
	return b.String()
}

// parsePacket turns raw packet lines into a Message. Lines without a colon
// belong to a "Response: Follows" command body and are collected under the
// synthetic "Output" key, matching how AMI itself reports CLI output.
func parsePacket(lines []string) *Message {
	m := &Message{}
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r\n")
		if ln == "" {
			continue
		}
		idx := strings.Index(ln, ":")
		if idx < 0 {
			m.Add("Output", ln)
			continue
		}
		key := strings.TrimSpace(ln[:idx])
		val := strings.TrimSpace(ln[idx+1:])
		m.Add(key, val)
	}
	return m
}
