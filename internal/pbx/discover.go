package pbx

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/adee42/ami-tsp/internal/ami"
	"github.com/adee42/ami-tsp/internal/config"
	"github.com/adee42/ami-tsp/internal/lines"
	"github.com/adee42/ami-tsp/internal/logx"
)

// Rejection records an endpoint that discovery deliberately did not export,
// and why. It exists so `amitsp-ctl discover` can answer the only question
// anyone asks of discovery: why is this phone not in my line list?
type Rejection struct {
	Endpoint string
	Reason   string
}

// discoverer reads the PJSIP endpoint list over AMI and turns it into registry
// entries. It is used both by the monitor's periodic scan and by the one-shot
// probe the TSP runs before it has a monitor at all.
type discoverer struct {
	cli *ami.Client
	cfg *config.Config
	reg *lines.Registry

	// refresh re-reads every endpoint's details instead of only those the
	// registry has nothing recorded for. It is for repairing a registry whose
	// stored names or contexts are wrong.
	refresh bool
}

// run performs one full scan.
//
// Endpoint details (caller ID) cost one round trip each, so they are only
// fetched for endpoints the registry has never seen. A steady-state rescan on
// a PBX with nothing new is a single action.
func (d *discoverer) run(ctx context.Context) ([]lines.Entry, []Rejection, error) {
	msgs, err := d.cli.ActionList(ctx, ami.NewMessage("Action", "PJSIPShowEndpoints"), "EndpointListComplete")
	if err != nil {
		return nil, nil, fmt.Errorf("discover: PJSIPShowEndpoints: %w", err)
	}

	var (
		found    []lines.Entry
		rejected []Rejection
	)
	for _, msg := range msgs {
		if !strings.EqualFold(msg.Event(), "EndpointList") {
			continue
		}
		name := strings.TrimSpace(msg.Get("ObjectName"))
		if name == "" {
			continue
		}
		if ok, reason := d.cfg.Discovery.Allows(name); !ok {
			rejected = append(rejected, Rejection{Endpoint: name, Reason: reason})
			continue
		}
		if d.cfg.Discovery.NeedsAOR() && strings.TrimSpace(msg.Get("Aor")) == "" {
			rejected = append(rejected, Rejection{Endpoint: name, Reason: "no AOR (looks like a trunk)"})
			continue
		}

		channel := "PJSIP/" + name
		e := lines.Entry{
			Line: config.Line{
				Channel:             channel,
				Extension:           name,
				AnswerMode:          d.cfg.Discovery.Defaults.AnswerMode,
				HoldMode:            d.cfg.Discovery.Defaults.HoldMode,
				AnswerNotifyHeaders: d.cfg.Discovery.Defaults.AnswerNotifyHeaders,
			},
			Source: lines.SourceDiscovered,
		}
		// Details cost a round trip each, so a rescan only asks about
		// endpoints it has nothing recorded for. When it does not ask, the
		// name and caller ID are left *empty* rather than filled with a
		// placeholder: Merge copies only non-empty fields, so a steady-state
		// scan must not claim to know a worse name than the one on file.
		if d.needsDetail(channel) {
			detail := d.endpointDetail(ctx, name)
			e.CallerIDName = detail.callerIDName
			e.CallerIDNum = detail.callerIDNum
			e.Context = detail.context
			if detail.callerIDName != "" {
				e.Name = fmt.Sprintf("%s (%s)", detail.callerIDName, name)
			} else {
				e.Name = "PJSIP " + name
			}
		}
		found = append(found, e)
	}
	return found, rejected, nil
}

// endpointFacts is what one PJSIPShowEndpoint round trip is worth.
type endpointFacts struct {
	callerIDName string
	callerIDNum  string
	context      string
}

// needsDetail reports whether an endpoint is worth a round trip. Details are
// fetched for endpoints the registry has never seen, and for ones recorded
// before the dialplan context was captured — otherwise a steady-state rescan
// is a single action.
func (d *discoverer) needsDetail(channel string) bool {
	if d.refresh || d.reg == nil {
		return true
	}
	i := d.reg.IndexOfChannel(channel)
	if i < 0 {
		return true
	}
	e, ok := d.reg.At(i)
	return ok && e.Context == ""
}

// endpointDetail reads the endpoint's caller ID and dialplan context. A
// failure is not fatal: the endpoint still becomes a line, just named after
// itself and originating into the globally configured context.
func (d *discoverer) endpointDetail(ctx context.Context, endpoint string) endpointFacts {
	msgs, err := d.cli.ActionList(ctx,
		ami.NewMessage("Action", "PJSIPShowEndpoint", "Endpoint", endpoint),
		"EndpointDetailComplete")
	if err != nil {
		logx.Debugf("discover: no detail for endpoint %s: %v", endpoint, err)
		return endpointFacts{}
	}
	for _, msg := range msgs {
		if !strings.EqualFold(msg.Event(), "EndpointDetail") {
			continue
		}
		name, num := parseCallerID(msg.Get("Callerid"))
		return endpointFacts{
			callerIDName: name,
			callerIDNum:  num,
			context:      strings.TrimSpace(msg.Get("Context")),
		}
	}
	return endpointFacts{}
}

// parseCallerID splits Asterisk's caller ID rendering, which is
// `"Display Name" <number>` with either half optional, into its two parts.
func parseCallerID(s string) (name, number string) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "<unknown>") {
		return "", ""
	}
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j >= 0 {
			number = strings.TrimSpace(s[i+1 : i+j])
			s = strings.TrimSpace(s[:i])
		}
	}
	name = strings.Trim(strings.TrimSpace(s), `"`)
	return blankUnknown(name), blankUnknown(number)
}

// blankUnknown maps Asterisk's placeholders for "not set" onto the empty
// string. The angle brackets are already gone from a parsed number, so both
// spellings have to be recognised.
func blankUnknown(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "unknown", "<unknown>":
		return ""
	}
	return s
}

// DiscoverOnce runs a single scan over a connection of its own, for callers
// that have no monitor: the TSP's first-run probe and `amitsp-ctl discover`.
//
// With refresh set, every endpoint's details are re-read rather than only
// those the registry has nothing on file for.
//
// It is bounded by ctx in its entirety, including waiting for the AMI login,
// because TapiSrv is blocked on it during provider enumeration.
func DiscoverOnce(ctx context.Context, cfg *config.Config, reg *lines.Registry, refresh bool) ([]lines.Entry, []Rejection, error) {
	ready := make(chan struct{})
	var once bool
	cli := ami.New(cfg.AMI, nil, func(up bool) {
		if up && !once {
			once = true
			close(ready)
		}
	})
	cli.Start()
	defer cli.Stop()

	select {
	case <-ready:
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("discover: no AMI connection within the time allowed: %w", ctx.Err())
	}

	d := &discoverer{cli: cli, cfg: cfg, reg: reg, refresh: refresh}
	return d.run(ctx)
}

// reachabilityCap bounds the connection test that guards the startup probe.
// It has to be well under Discovery.InitialTimeoutSec to be worth doing: the
// case it exists for is a firewall that blackholes packets, where a dial would
// otherwise hang for the whole probe window.
const reachabilityCap = 3 * time.Second

// BuildRegistry assembles the line registry at startup: the persisted device
// list, overlaid with whatever lines[] configures, and — when probe is set —
// merged with a live scan of the PBX.
//
// The PBX is the source of truth on every start, not just the first. The
// persisted registry is what makes that safe: it pins each device's slot and
// permanent ID, which TAPI applications store their per-line preferences
// against, so a scan can only ever add to the list or mark part of it absent.
// It is also the fallback when the PBX cannot be reached at all, which is the
// difference between a workstation showing its phones as out of service and
// showing no telephony whatsoever.
//
// The TSP needs the probe — TSPI_providerEnumDevices has to report a device
// count before any connection exists, and a phone added while the service was
// stopped would otherwise be missing from that first enumeration. Diagnostics
// pass probe=false and read what is on file.
func BuildRegistry(cfg *config.Config, probe bool) (*lines.Registry, error) {
	reg, err := lines.Load(config.RegistryPath())
	if err != nil {
		return nil, err
	}
	reg.ApplyConfig(cfg.Lines)

	if probe && cfg.Discovery.IsEnabled() {
		probeRegistry(cfg, reg)
	}

	if err := reg.Save(); err != nil {
		// Not fatal: the provider works, it just has to rediscover next time.
		logx.Errorf("discover: cannot persist line registry: %v", err)
	}
	return reg, nil
}

// probeRegistry folds one live scan into reg, or leaves it exactly as it was.
func probeRegistry(cfg *config.Config, reg *lines.Registry) {
	// Somebody is waiting on this: TapiSrv is blocked inside
	// TSPI_providerEnumDevices for its whole duration.
	dialTimeout := time.Duration(cfg.AMI.ConnectTimeoutSec) * time.Second
	if dialTimeout > reachabilityCap {
		dialTimeout = reachabilityCap
	}
	if !ami.Reachable(cfg.AMI, dialTimeout) {
		logx.Warnf("discover: %s:%d unreachable, enumerating %d known device(s) from the registry",
			cfg.AMI.Host, cfg.AMI.Port, reg.Len())
		return
	}

	timeout := time.Duration(cfg.Discovery.InitialTimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	found, _, err := DiscoverOnce(ctx, cfg, reg, false)
	if err != nil {
		// Merge must not run here. A scan that failed saw no endpoints, and
		// merging that would mark every device absent because the network
		// blinked.
		logx.Warnf("discover: startup probe failed (%v); enumerating %d known device(s) from the registry",
			err, reg.Len())
		return
	}

	added, gone := reg.Merge(found)

	// Only now, having actually heard from the PBX, is absence evidence of
	// anything. PJSIPShowEndpoints lists endpoints whatever their registration
	// state, so a phone that is merely unplugged still appears here; a device
	// missing from a successful scan has been deleted from the PBX.
	for _, e := range reg.PruneAbsent() {
		logx.Infof("discover: removed %s (%s) from the registry, no longer configured on the PBX",
			e.Channel, e.Name)
	}

	logx.Infof("discover: startup probe found %d endpoint(s), %d new, %d no longer present (%d total)",
		len(found), len(added), len(gone), reg.Len())
}

// DialplanEntry is one line of the PBX's dialplan: either an extension, or an
// include of another context. Both matter — a context made only of includes
// still reaches every extension they contain, because Asterisk follows
// includes when it checks whether an Originate's extension exists.
type DialplanEntry struct {
	Context   string
	Extension string
	Priority  string
	App       string
	Includes  string
}

// IsInclude reports whether the entry is an `include =>` rather than an
// extension.
func (e DialplanEntry) IsInclude() bool { return e.Includes != "" }

// ShowDialplan asks the PBX for its dialplan, optionally narrowed to one
// context. It is a diagnostic: "Extension does not exist" from an Originate
// means the configured context and the destination do not resolve, and this is
// how to find out what would.
//
// It needs read=dialplan on the manager account; without it Asterisk refuses
// the action and the error says so.
func ShowDialplan(ctx context.Context, cfg *config.Config, context_ string) ([]DialplanEntry, error) {
	ready := make(chan struct{})
	var once bool
	cli := ami.New(cfg.AMI, nil, func(up bool) {
		if up && !once {
			once = true
			close(ready)
		}
	})
	cli.Start()
	defer cli.Stop()

	select {
	case <-ready:
	case <-ctx.Done():
		return nil, fmt.Errorf("dialplan: no AMI connection within the time allowed: %w", ctx.Err())
	}

	act := ami.NewMessage("Action", "ShowDialPlan")
	if context_ != "" {
		act.Add("Context", context_)
	}
	msgs, err := cli.ActionList(ctx, act, "ShowDialPlanComplete")
	if err != nil {
		return nil, fmt.Errorf("dialplan: ShowDialPlan: %w", err)
	}

	var out []DialplanEntry
	for _, msg := range msgs {
		if !strings.EqualFold(msg.Event(), "ListDialplan") {
			continue
		}
		out = append(out, DialplanEntry{
			Context:   msg.Get("Context"),
			Extension: msg.Get("Extension"),
			Priority:  msg.Get("Priority"),
			App:       msg.Get("Application"),
			Includes:  firstNonEmpty(msg.Get("IncludeContext"), msg.Get("Includecontext")),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- scan loop

// requestScan asks for a scan as soon as the scan loop is free. The channel is
// depth one, so a burst of phones registering coalesces into a single pass.
func (m *Monitor) requestScan() {
	select {
	case m.rescan <- struct{}{}:
	default:
	}
}

// scanLoop owns discovery for the life of the monitor. It scans when the link
// comes up, whenever something suggests the device list changed, and on a
// timer as a backstop for changes that produce no AMI event at all (an
// endpoint added in the config and reloaded, but never registered).
func (m *Monitor) scanLoop() {
	defer m.wg.Done()
	defer logx.Recover("discover: scan loop")

	interval := time.Duration(m.cfg.Discovery.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	// A short settle after a trigger: a `pjsip reload` produces a burst of
	// contact events and there is no point scanning once per phone.
	const debounce = 5 * time.Second

	for {
		select {
		case <-m.stopCh:
			return
		case <-tick.C:
		case <-m.rescan:
			select {
			case <-time.After(debounce):
			case <-m.stopCh:
				return
			}
			// Drain anything that arrived while settling.
			select {
			case <-m.rescan:
			default:
			}
		}

		if !m.cli.Connected() {
			continue
		}
		m.runScan()
	}
}

// runScan performs one scan and folds the result into the registry, announcing
// what changed.
func (m *Monitor) runScan() {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(m.cfg.AMI.ActionTimeoutSec)*time.Second*4)
	defer cancel()

	d := &discoverer{cli: m.cli, cfg: m.cfg, reg: m.reg}
	found, rejected, err := d.run(ctx)
	if err != nil {
		logx.Warnf("discover: scan failed: %v", err)
		return
	}

	added, gone := m.reg.Merge(found)
	// Save unconditionally: a scan that adds no devices can still have learned
	// something that matters, such as an endpoint's dialplan context. Save is
	// a no-op when nothing actually changed.
	if err := m.reg.Save(); err != nil {
		// The devices are live either way; the cost of a failed save is that
		// the next start has to rediscover them.
		logx.Errorf("discover: cannot persist line registry: %v", err)
	}
	logx.Infof("discover: %d endpoint(s), %d rejected, %d new, %d gone",
		len(found), len(rejected), len(added), len(gone))
	for _, r := range rejected {
		logx.Debugf("discover: skipped %s: %s", r.Endpoint, r.Reason)
	}

	for _, i := range gone {
		if e, ok := m.reg.At(i); ok {
			logx.Infof("discover: line [%d] %s is gone from the PBX, reporting out of service", i, e.Channel)
		}
	}

	// LINE_CREATE has to happen exactly once per device, and before anything
	// else is said about that line.
	m.mu.Lock()
	// A rejected endpoint is one discovery has deliberately passed over, not
	// a new phone; activity on it (every call over a trunk) must not keep
	// asking for scans.
	for _, r := range rejected {
		m.scanTried[strings.ToLower("PJSIP/"+r.Endpoint)] = true
	}
	for _, i := range added {
		if e, ok := m.reg.At(i); ok {
			logx.Infof("discover: new line [%d] %s (%s)", i, e.Channel, e.Name)
		}
		m.emit(Event{Type: EventLineAdded, LineIndex: i})
	}
	m.mu.Unlock()

	m.publishLineStates()
}

// publishLineStates reports the presence of every line whose presence differs
// from what was last reported, and of every line not reported yet.
//
// It compares against the registry as a whole rather than against what the
// last scan changed, so a device that comes back is reported as surely as one
// that goes. Events are never dropped (see emit), so a line that has been
// reported once does not need restating; on a PBX with hundreds of devices
// that restating used to put hundreds of events in front of every call event
// after each scan.
func (m *Monitor) publishLineStates() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.reg.Entries() {
		if prev, ok := m.published[i]; ok && prev == e.Present {
			continue
		}
		m.published[i] = e.Present
		m.emit(Event{Type: EventLineState, LineIndex: i, Up: e.Present})
	}
}

// noteDeviceActivity triggers a scan when an event mentions a PJSIP device the
// registry does not know about. This is what makes a newly plugged-in phone
// appear within seconds rather than at the next tick. Caller holds m.mu.
//
// Each unknown device asks once. These events fire on every call, so a device
// that is unknown for a reason a scan will not change — a trunk, an endpoint
// the filters exclude — would otherwise keep the PBX answering
// PJSIPShowEndpoints every few seconds. The periodic scan still covers it.
func (m *Monitor) noteDeviceActivity(device string) {
	device = strings.TrimSpace(device)
	if device == "" || !m.cfg.Discovery.IsEnabled() {
		return
	}
	if strings.Contains(device, "/") {
		// A qualified device name from some other channel driver is not ours.
		if !strings.HasPrefix(strings.ToLower(device), "pjsip/") {
			return
		}
	} else if strings.Contains(device, ":") {
		// Queue:sales_avail, Custom:DND1001, park:701@parkedcalls: device
		// states of things that are not endpoints at all.
		return
	} else {
		// ContactStatus and friends report the bare endpoint name.
		device = "PJSIP/" + device
	}
	key := strings.ToLower(device)
	if m.scanTried[key] || m.reg.IndexOfChannel(device) >= 0 {
		return
	}
	m.scanTried[key] = true
	logx.Debugf("discover: unknown device %s seen, scheduling a scan", device)
	m.requestScan()
}
