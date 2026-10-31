// Package config loads the TSP configuration.
//
// The provider is loaded by TapiSrv, so it cannot prompt for anything and has
// no working directory worth speaking of. Configuration therefore comes from a
// JSON file whose location is resolved in a fixed order (see Path).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Config is the whole file.
type Config struct {
	AMI       AMI       `json:"ami"`
	Dialplan  Dialplan  `json:"dialplan"`
	Log       Log       `json:"log"`
	Discovery Discovery `json:"discovery"`
	TAPI      TAPI      `json:"tapi"`
	Lines     []Line    `json:"lines"`
}

// TAPI holds what the provider tells TAPI applications about its devices.
type TAPI struct {
	// MaxCallsPerLine is the number of simultaneous calls a line device
	// reports in LINEDEVCAPS and tracks. A call beyond it is not shown to
	// applications, so a line shared by many callers (a reception or queue
	// device) wants this raised.
	MaxCallsPerLine int `json:"max_calls_per_line"`
}

// maxCallsCeiling bounds MaxCallsPerLine. TAPI sets no limit, but every
// application sizes its per-line call list from the advertised value.
const maxCallsCeiling = 256

// AMI describes how to reach the Asterisk Manager Interface.
type AMI struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Secret   string `json:"secret"`

	// TLS connects to Asterisk's TLS manager port (tlsenable=yes in manager.conf).
	TLS                bool `json:"tls"`
	InsecureSkipVerify bool `json:"insecure_skip_verify"`

	ConnectTimeoutSec int `json:"connect_timeout_sec"`
	ActionTimeoutSec  int `json:"action_timeout_sec"`
	KeepaliveSec      int `json:"keepalive_sec"`
	ReconnectMinSec   int `json:"reconnect_min_sec"`
	ReconnectMaxSec   int `json:"reconnect_max_sec"`

	// ResyncSec is how often the tracked calls are compared against the PBX's
	// own channel list (CoreShowChannels), which repairs anything the event
	// stream failed to convey. It also runs every time the link comes up.
	ResyncSec int `json:"resync_sec"`

	// EventFilter asks Asterisk to send only the events the provider uses
	// (the Filter action, which needs write=system). On a busy PBX the full
	// stream is dominated by dialplan, RTCP and CDR events nothing here reads.
	// It defaults to on.
	EventFilter *bool `json:"event_filter"`
}

// FilterEvents reports whether the event filter should be installed.
func (a *AMI) FilterEvents() bool { return a.EventFilter == nil || *a.EventFilter }

// Dialplan controls how outbound calls are placed via Action: Originate.
type Dialplan struct {
	Context            string       `json:"context"`
	Priority           int          `json:"priority"`
	OriginateTimeoutMS int          `json:"originate_timeout_ms"`
	NumberRules        []NumberRule `json:"number_rules"`

	compiled []compiledRule
}

// NumberRule rewrites the destination address handed over by the TAPI
// application into something the Asterisk dialplan understands. TAPI apps
// commonly pass canonical numbers ("+49 30 1234567") while a dialplan wants
// "004930123456" or a bare extension.
type NumberRule struct {
	Match   string `json:"match"`
	Replace string `json:"replace"`
}

type compiledRule struct {
	re      *regexp.Regexp
	replace string
}

type Log struct {
	File  string `json:"file"`
	Level string `json:"level"`
}

// Discovery controls automatic enumeration of PJSIP endpoints as TAPI line
// devices. Discovered lines are remembered in the line registry (see
// internal/lines) so that their device order and permanent IDs survive a
// restart, which TAPI applications depend on.
type Discovery struct {
	// Enabled defaults to true when the block is absent, so an existing
	// configuration file starts discovering without being edited. Set it to
	// false for the old behaviour of exporting only Lines.
	Enabled *bool `json:"enabled"`

	// IntervalSec is how often the endpoint list is re-read. Endpoint
	// activity (a phone registering, a device state change) triggers a scan
	// sooner, so this is a backstop rather than the main mechanism.
	IntervalSec int `json:"interval_sec"`

	// InitialTimeoutSec bounds the one synchronous scan performed during
	// TSPI_providerEnumDevices when the registry is empty. TapiSrv is waiting
	// on us for the whole of it, so it is deliberately short.
	InitialTimeoutSec int `json:"initial_timeout_sec"`

	// Include, when non-empty, restricts discovery to endpoints matching one
	// of these patterns. Exclude then removes matches from what is left.
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`

	// RequireAOR skips endpoints that have no AOR configured. Trunk-side
	// endpoints usually have none, desk phones always do.
	RequireAOR *bool `json:"require_aor"`

	// Defaults are applied to every discovered line. Only the fields that
	// cannot be learned from the PBX are worth setting here.
	Defaults DiscoveryDefaults `json:"defaults"`

	includeRE []*regexp.Regexp
	excludeRE []*regexp.Regexp
}

// DiscoveryDefaults carries the per-line settings that AMI cannot report.
type DiscoveryDefaults struct {
	AnswerMode          string            `json:"answer_mode"`
	HoldMode            string            `json:"hold_mode"`
	AnswerNotifyHeaders map[string]string `json:"answer_notify_headers"`
}

// IsEnabled reports whether discovery should run.
func (d *Discovery) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

// NeedsAOR reports whether endpoints without an AOR are skipped.
func (d *Discovery) NeedsAOR() bool { return d.RequireAOR == nil || *d.RequireAOR }

// Allows reports whether an endpoint name passes the include/exclude filters.
// The reason is suitable for logging and for `amitsp-ctl discover`.
func (d *Discovery) Allows(endpoint string) (bool, string) {
	if len(d.includeRE) > 0 {
		matched := false
		for _, re := range d.includeRE {
			if re.MatchString(endpoint) {
				matched = true
				break
			}
		}
		if !matched {
			return false, "no include pattern matched"
		}
	}
	for _, re := range d.excludeRE {
		if re.MatchString(endpoint) {
			return false, "excluded by " + re.String()
		}
	}
	return true, ""
}

// Line is one TAPI line device, backed by one Asterisk device.
type Line struct {
	// Name is what the user sees in the Windows dialer / CRM line list.
	Name string `json:"name"`

	// Channel is the Asterisk device channel *without* the per-call suffix,
	// e.g. "PJSIP/1001" or "SIP/1001". Channel-to-line matching is done on
	// the "Channel-" prefix, case-insensitively.
	Channel string `json:"channel"`

	// Extension is the number this device is reachable at. Used as caller ID
	// and for logging only.
	Extension string `json:"extension"`

	CallerIDName string `json:"callerid_name"`
	CallerIDNum  string `json:"callerid_num"`

	// Context is the dialplan context an outbound call from this device is
	// placed into, overriding dialplan.context. Discovery fills it in from the
	// endpoint's own configuration, which is the context the phone dials into
	// when somebody picks up the handset — so a number originated through it
	// is treated exactly as if it had been dialled on the keypad.
	Context string `json:"context"`

	// PermanentID must be stable and unique across lines; TAPI persists app
	// line preferences against it. Defaults to 1-based index if zero.
	PermanentID uint32 `json:"permanent_id"`

	// explicitID records that PermanentID came from the file rather than from
	// the positional default. The line registry needs the distinction: an ID
	// the administrator wrote down outranks one it allocated itself, but a
	// positional default must not, or editing lines[] would renumber devices.
	explicitID bool

	// AnswerMode selects how TSPI_lineAnswer is implemented for calls
	// offering at this device:
	//
	//	""|"none"     -> report LINEERR_OPERATIONUNAVAIL (honest default)
	//	"pjsip-notify"-> Action: PJSIPNotify with an auto-answer NOTIFY
	//	"sip-notify"  -> Action: SIPnotify (chan_sip) with the same
	//
	// The NOTIFY approach only works on phones configured to accept it
	// (Snom "Event: talk", Yealink/Grandstream equivalents).
	AnswerMode string `json:"answer_mode"`

	// AnswerNotifyHeaders are the NOTIFY headers sent for the notify answer
	// modes. Defaults to {"Event": "talk"} which Snom and Yealink accept.
	AnswerNotifyHeaders map[string]string `json:"answer_notify_headers"`

	// HoldMode selects TSPI_lineHold/Unhold behaviour. It takes the same
	// values as AnswerMode -- "" or "none" reports LINEERR_OPERATIONUNAVAIL,
	// "pjsip-notify" or "sip-notify" send Event: hold and Event: talk. Any
	// other value is rejected at the point of use, so it must not be guessed
	// at: the capability bits promise the application something that would
	// then fail.
	HoldMode string `json:"hold_mode"`
}

// Path resolves the configuration file location:
//
//  1. %AMITSP_CONFIG%
//  2. %ProgramData%\AmiTSP\ami-tsp.json
func Path() string {
	if p := strings.TrimSpace(os.Getenv("AMITSP_CONFIG")); p != "" {
		return p
	}
	return filepath.Join(DataDir(), "ami-tsp.json")
}

// RegistryPath is where the discovered line registry is persisted. It must be
// writable by TapiSrv, and it must survive a restart: TAPI applications key
// their per-line preferences off the permanent IDs recorded in it.
func RegistryPath() string {
	if p := strings.TrimSpace(os.Getenv("AMITSP_REGISTRY")); p != "" {
		return p
	}
	return filepath.Join(DataDir(), "lines.json")
}

// DataDir is where the config, log and state live. TapiSrv runs as
// LocalSystem, which can always write here.
func DataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "AmiTSP")
}

// TrimBOM removes a leading UTF-8 byte order mark.
//
// Notepad and PowerShell's Out-File both write one, encoding/json rejects it
// outright, and the administrator editing these files is on Windows. Without
// this a stray BOM takes the provider down to zero line devices and leaves
// "invalid character 'ï'" in the log to explain it.
func TrimBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}

// Load reads and validates the configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	raw = TrimBOM(raw)
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		// Retry leniently: an unknown key should be a warning, not a reason
		// for the whole provider to fail to load.
		if err2 := json.Unmarshal(raw, &c); err2 != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err2)
		}
	}
	if err := c.normalise(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) normalise() error {
	if c.AMI.Host == "" {
		return fmt.Errorf("config: ami.host is required")
	}
	if c.AMI.Username == "" {
		return fmt.Errorf("config: ami.username is required")
	}
	if c.AMI.Port == 0 {
		if c.AMI.TLS {
			c.AMI.Port = 5039
		} else {
			c.AMI.Port = 5038
		}
	}
	setDefaultInt(&c.AMI.ConnectTimeoutSec, 10)
	setDefaultInt(&c.AMI.ActionTimeoutSec, 15)
	setDefaultInt(&c.AMI.KeepaliveSec, 30)
	setDefaultInt(&c.AMI.ReconnectMinSec, 2)
	setDefaultInt(&c.AMI.ReconnectMaxSec, 60)
	setDefaultInt(&c.AMI.ResyncSec, 60)

	setDefaultInt(&c.TAPI.MaxCallsPerLine, 4)
	if c.TAPI.MaxCallsPerLine > maxCallsCeiling {
		c.TAPI.MaxCallsPerLine = maxCallsCeiling
	}

	if c.Dialplan.Context == "" {
		c.Dialplan.Context = "from-internal"
	}
	setDefaultInt(&c.Dialplan.Priority, 1)
	setDefaultInt(&c.Dialplan.OriginateTimeoutMS, 30000)
	if c.Dialplan.NumberRules == nil {
		// Sensible German default: strip formatting, turn +49… into 0049….
		c.Dialplan.NumberRules = []NumberRule{
			{Match: `[^0-9+*#]`, Replace: ``},
			{Match: `^\+`, Replace: `00`},
		}
	}
	for _, r := range c.Dialplan.NumberRules {
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return fmt.Errorf("config: dialplan.number_rules %q: %w", r.Match, err)
		}
		c.Dialplan.compiled = append(c.Dialplan.compiled, compiledRule{re: re, replace: r.Replace})
	}

	if c.Log.File == "" {
		c.Log.File = filepath.Join(DataDir(), "ami-tsp.log")
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}

	if err := c.Discovery.normalise(); err != nil {
		return err
	}

	// With discovery on, an empty lines list is the normal case: the PBX is
	// the source of truth and lines[] only carries overrides.
	if len(c.Lines) == 0 && !c.Discovery.IsEnabled() {
		return fmt.Errorf("config: at least one entry in lines is required when discovery is disabled")
	}
	seen := map[uint32]bool{}
	for i := range c.Lines {
		l := &c.Lines[i]
		if l.Channel == "" {
			return fmt.Errorf("config: lines[%d].channel is required", i)
		}
		l.Normalise()
		l.explicitID = l.PermanentID != 0
		if l.PermanentID == 0 {
			l.PermanentID = uint32(i + 1)
		}
		if seen[l.PermanentID] {
			return fmt.Errorf("config: lines[%d].permanent_id %d is not unique", i, l.PermanentID)
		}
		seen[l.PermanentID] = true
	}
	return nil
}

// HasExplicitPermanentID reports whether permanent_id was set in the file.
func (l *Line) HasExplicitPermanentID() bool { return l.explicitID }

// Normalise fills in the fields that can be derived from Channel. It is used
// both for configured lines and for lines discovered over AMI, so that the two
// end up indistinguishable to the rest of the provider.
func (l *Line) Normalise() {
	l.Channel = strings.TrimRight(l.Channel, "-")
	if l.Extension == "" {
		// "PJSIP/1001" -> "1001"
		if idx := strings.LastIndex(l.Channel, "/"); idx >= 0 {
			l.Extension = l.Channel[idx+1:]
		}
	}
	if l.Name == "" {
		l.Name = fmt.Sprintf("Asterisk %s", l.Extension)
	}
	if l.CallerIDNum == "" {
		l.CallerIDNum = l.Extension
	}
	if len(l.AnswerNotifyHeaders) == 0 {
		l.AnswerNotifyHeaders = map[string]string{"Event": "talk"}
	}
}

func (d *Discovery) normalise() error {
	setDefaultInt(&d.IntervalSec, 300)
	setDefaultInt(&d.InitialTimeoutSec, 8)
	if d.Exclude == nil {
		// Conservative defaults: the names installations give to the endpoints
		// that face a carrier rather than a desk.
		d.Exclude = []string{`(?i)trunk`, `(?i)gateway`, `(?i)^gw`, `(?i)provider`}
	}
	for _, pats := range []struct {
		src []string
		dst *[]*regexp.Regexp
		key string
	}{
		{d.Include, &d.includeRE, "include"},
		{d.Exclude, &d.excludeRE, "exclude"},
	} {
		for _, p := range pats.src {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("config: discovery.%s %q: %w", pats.key, p, err)
			}
			*pats.dst = append(*pats.dst, re)
		}
	}
	if d.Defaults.AnswerMode == "" {
		d.Defaults.AnswerMode = "none"
	}
	if d.Defaults.HoldMode == "" {
		d.Defaults.HoldMode = "none"
	}
	if len(d.Defaults.AnswerNotifyHeaders) == 0 {
		d.Defaults.AnswerNotifyHeaders = map[string]string{"Event": "talk"}
	}
	return nil
}

// RewriteNumber applies the configured number rules in order.
func (d *Dialplan) RewriteNumber(s string) string {
	s = strings.TrimSpace(s)
	for _, r := range d.compiled {
		s = r.re.ReplaceAllString(s, r.replace)
	}
	return s
}

func setDefaultInt(p *int, def int) {
	if *p <= 0 {
		*p = def
	}
}
