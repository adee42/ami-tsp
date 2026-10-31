package lines

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adee42/ami-tsp/internal/config"
)

// The config package is exercised here too, via Load and TrimBOM.

// loadCfgLines runs a lines[] fragment through the real configuration loader,
// so the test sees exactly what the provider would: defaults filled in, and
// the distinction between a written-down permanent_id and a positional one.
func loadCfgLines(t *testing.T, linesJSON string) []config.Line {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ami-tsp.json")
	body := `{"ami":{"host":"pbx","username":"tapi"},"lines":` + linesJSON + `}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Lines
}

// discovered builds what a scan would hand to Merge.
func discovered(channels ...string) []Entry {
	out := make([]Entry, 0, len(channels))
	for _, ch := range channels {
		e := Entry{Line: config.Line{Channel: ch}, Source: SourceDiscovered}
		e.Line.Normalise()
		out = append(out, e)
	}
	return out
}

func channelsOf(r *Registry) []string {
	var out []string
	for _, e := range r.Entries() {
		out = append(out, e.Channel)
	}
	return out
}

func permIDs(r *Registry) map[string]uint32 {
	out := map[string]uint32{}
	for _, e := range r.Entries() {
		out[e.Channel] = e.PermanentID
	}
	return out
}

// TestOrderAndIDsSurviveRestart is the invariant everything else rests on: a
// device's index and permanent ID must be the same after a restart, whatever
// order the PBX reports endpoints in and whatever happened to lines[].
func TestOrderAndIDsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lines.json")

	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Merge(discovered("PJSIP/1001", "PJSIP/1002", "PJSIP/1003"))
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	wantOrder := channelsOf(r)
	wantIDs := permIDs(r)

	// Restart: the PBX now answers in a different order, one endpoint is
	// gone, and a new one has appeared.
	r2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r2.Merge(discovered("PJSIP/1003", "PJSIP/2000", "PJSIP/1001"))

	got := channelsOf(r2)
	for i, ch := range wantOrder {
		if got[i] != ch {
			t.Fatalf("device %d moved from %s to %s", i, ch, got[i])
		}
	}
	if got[3] != "PJSIP/2000" {
		t.Fatalf("new device should have been appended, got %v", got)
	}
	for ch, id := range wantIDs {
		if permIDs(r2)[ch] != id {
			t.Errorf("%s permanent ID changed from %d to %d", ch, id, permIDs(r2)[ch])
		}
	}
	if permIDs(r2)["PJSIP/2000"] == 0 {
		t.Error("new device got no permanent ID")
	}
}

// TestFieldUpdatesArePersisted: a rescan that adds and removes nothing can
// still have learned something that matters — an endpoint's dialplan context,
// without which outbound calls are originated into the wrong context and
// Asterisk rejects them.
func TestFieldUpdatesArePersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lines.json")
	r, _ := Load(path)
	r.Merge(discovered("PJSIP/81"))
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	// A later scan learns the context. Nothing is added or removed.
	withContext := discovered("PJSIP/81")
	withContext[0].Context = "DLPN_DialPlan81"
	added, gone := r.Merge(withContext)
	if len(added) != 0 || len(gone) != 0 {
		t.Fatalf("expected no device churn, got added=%v gone=%v", added, gone)
	}
	if e, _ := r.At(0); e.Context != "DLPN_DialPlan81" {
		t.Fatalf("context not applied in memory, got %q", e.Context)
	}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := reloaded.At(0); e.Context != "DLPN_DialPlan81" {
		t.Errorf("context did not survive a restart, got %q", e.Context)
	}
}

// TestRescanDoesNotDowngradeKnownFields: a rescan skips the detail lookup for
// endpoints it already has, so it reports only the channel. Those blanks must
// not overwrite the name and caller ID already on file.
func TestRescanDoesNotDowngradeKnownFields(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))

	full := discovered("PJSIP/81")
	full[0].Name = "Telefon-81 (81)"
	full[0].CallerIDName = "Telefon-81"
	full[0].Context = "DLPN_DialPlan81"
	r.Merge(full)

	// The steady-state rescan: channel and extension only.
	sparse := []Entry{{Line: config.Line{Channel: "PJSIP/81", Extension: "81"}}}
	r.Merge(sparse)

	e, _ := r.At(0)
	if e.Name != "Telefon-81 (81)" {
		t.Errorf("name downgraded to %q", e.Name)
	}
	if e.CallerIDName != "Telefon-81" {
		t.Errorf("caller ID name downgraded to %q", e.CallerIDName)
	}
	if e.Context != "DLPN_DialPlan81" {
		t.Errorf("context lost, got %q", e.Context)
	}
}

// TestPruneRefusesWithoutAScan is the guard that stops a boot-time network
// outage from erasing the estate: straight after a load every entry is marked
// absent, because nothing has been confirmed yet.
func TestPruneRefusesWithoutAScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lines.json")
	r, _ := Load(path)
	r.Merge(discovered("PJSIP/81", "PJSIP/83"))
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if removed := reloaded.PruneAbsent(); len(removed) != 0 {
		t.Errorf("pruned %d device(s) without a scan having run", len(removed))
	}
	if reloaded.Len() != 2 {
		t.Fatalf("registry lost devices: %d remain", reloaded.Len())
	}
}

// TestPruneRemovesOnlyDeletedDevices covers what a service restart does after
// a phone is deleted from the PBX.
func TestPruneRemovesOnlyDeletedDevices(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.Merge(discovered("PJSIP/81", "PJSIP/83", "PJSIP/84"))
	r.ApplyConfig(loadCfgLines(t, `[{"channel":"PJSIP/manual","name":"Front desk"}]`))

	before := permIDs(r)

	// 83 has been deleted from the PBX; the manual line is not discoverable at
	// all and must survive regardless.
	r.Merge(discovered("PJSIP/81", "PJSIP/84"))
	removed := r.PruneAbsent()

	if len(removed) != 1 || removed[0].Channel != "PJSIP/83" {
		t.Fatalf("expected only PJSIP/83 to be pruned, got %v", removed)
	}
	if got := channelsOf(r); len(got) != 3 {
		t.Fatalf("expected 3 devices left, got %v", got)
	}
	if r.IndexOfChannel("PJSIP/manual") < 0 {
		t.Error("a configured line was pruned")
	}

	// The survivors keep their identities; only their positions move.
	for _, ch := range []string{"PJSIP/81", "PJSIP/84", "PJSIP/manual"} {
		if permIDs(r)[ch] != before[ch] {
			t.Errorf("%s permanent ID changed from %d to %d", ch, before[ch], permIDs(r)[ch])
		}
	}

	// The channel index must have been rebuilt, or lookups resolve to the
	// wrong device after the shift.
	for i, e := range r.Entries() {
		if got := r.IndexOfChannel(e.Channel); got != i {
			t.Errorf("%s resolves to index %d but sits at %d", e.Channel, got, i)
		}
	}
	if r.IndexOfChannel("PJSIP/83") >= 0 {
		t.Error("the pruned channel still resolves")
	}
}

// TestLoadToleratesBOM: a registry hand-edited in Notepad or rewritten by
// PowerShell picks up a UTF-8 BOM, and a load failure here costs every line
// device on the machine.
func TestLoadToleratesBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lines.json")
	r, _ := Load(path)
	r.Merge(discovered("PJSIP/81"))
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte{0xEF, 0xBB, 0xBF}, raw...), 0o644); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("a byte order mark broke the registry: %v", err)
	}
	if reloaded.Len() != 1 {
		t.Errorf("expected 1 device after reload, got %d", reloaded.Len())
	}
}

// TestMergeIsTheOnlyThingThatMarksAbsence pins the rule the startup probe
// depends on: absence is concluded from a *successful* scan that did not list a
// device. A failed scan must not be merged at all, or a network blink would
// report every phone in the building out of service.
func TestMergeIsTheOnlyThingThatMarksAbsence(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.Merge(discovered("PJSIP/81", "PJSIP/83"))
	for i := 0; i < r.Len(); i++ {
		if e, _ := r.At(i); !e.Present {
			t.Fatalf("device %d should be present after a successful scan", i)
		}
	}

	// What a failed probe hands over is nothing at all. Merging it would be
	// the bug; the caller must skip Merge entirely. Assert the shape of that
	// bug so the guard cannot be quietly removed.
	_, gone := r.Merge(nil)
	if len(gone) != 2 {
		t.Fatalf("merging an empty scan should mark both absent (that is why it must not be called): %v", gone)
	}
}

// TestLinesWithExtension covers the lookup `amitsp-ctl dial` uses.
func TestLinesWithExtension(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.Merge(discovered("PJSIP/81", "PJSIP/83"))

	if got := r.LinesWithExtension("83"); len(got) != 1 || got[0] != 1 {
		t.Errorf("LinesWithExtension(83) = %v, want [1]", got)
	}
	if got := r.LinesWithExtension("99"); len(got) != 0 {
		t.Errorf("unknown extension matched %v", got)
	}
	if got := r.LinesWithExtension(""); len(got) != 0 {
		t.Errorf("empty extension matched %v", got)
	}

	// Two devices can share an extension; the caller must see both so it can
	// ask which one rather than guess.
	dup := []Entry{{Line: config.Line{Channel: "PJSIP/81-desk", Extension: "81"}}}
	r.Merge(dup)
	if got := r.LinesWithExtension("81"); len(got) != 2 {
		t.Errorf("shared extension should report both lines, got %v", got)
	}
}

// TestVanishedDeviceKeepsItsSlot: TAPI 2.x has no way to withdraw a device, so
// a disappeared endpoint must stay put and only be marked absent.
func TestVanishedDeviceKeepsItsSlot(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.Merge(discovered("PJSIP/1001", "PJSIP/1002"))

	_, gone := r.Merge(discovered("PJSIP/1001"))
	if len(gone) != 1 || gone[0] != 1 {
		t.Fatalf("expected line 1 reported gone, got %v", gone)
	}
	if r.Len() != 2 {
		t.Fatalf("device count changed to %d", r.Len())
	}
	if e, _ := r.At(1); e.Present {
		t.Error("vanished device still marked present")
	}

	// It comes back: same slot, same ID, no second device.
	before, _ := r.At(1)
	added, _ := r.Merge(discovered("PJSIP/1001", "PJSIP/1002"))
	if len(added) != 0 {
		t.Errorf("returning device was added again: %v", added)
	}
	after, _ := r.At(1)
	if after.PermanentID != before.PermanentID || !after.Present {
		t.Errorf("returning device not restored in place: %+v", after)
	}
}

// TestConfigOverridesDoNotRenumber: editing lines[] must change what a device
// is called, never which slot or permanent ID it occupies.
func TestConfigOverridesDoNotRenumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lines.json")
	r, _ := Load(path)
	r.Merge(discovered("PJSIP/1001", "PJSIP/1002"))
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	wantIDs := permIDs(r)

	r2, _ := Load(path)
	r2.ApplyConfig(loadCfgLines(t, `[{"channel":"PJSIP/1002","name":"Reception"}]`))

	if got := channelsOf(r2); got[0] != "PJSIP/1001" || got[1] != "PJSIP/1002" {
		t.Fatalf("configuration reordered devices: %v", got)
	}
	e, _ := r2.At(1)
	if e.Name != "Reception" {
		t.Errorf("override not applied, name is %q", e.Name)
	}
	if e.Source != SourceConfig {
		t.Errorf("overridden line should be sourced from config, got %q", e.Source)
	}
	// The positional ID config invents for an unnumbered line (here 1) must
	// not displace the ID the registry already handed out.
	if e.PermanentID != wantIDs["PJSIP/1002"] {
		t.Errorf("permanent ID changed from %d to %d", wantIDs["PJSIP/1002"], e.PermanentID)
	}

	// A discovery scan must not undo the override.
	r2.Merge(discovered("PJSIP/1001", "PJSIP/1002"))
	if e, _ := r2.At(1); e.Name != "Reception" {
		t.Errorf("discovery overwrote the configured name with %q", e.Name)
	}
}

// TestExplicitPermanentIDWins: an ID the administrator wrote down outranks one
// the registry allocated, because applications may already be pinned to it.
func TestExplicitPermanentIDWins(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.Merge(discovered("PJSIP/1001"))

	r.ApplyConfig(loadCfgLines(t, `[{"channel":"PJSIP/1001","permanent_id":4242}]`))

	if e, _ := r.At(0); e.PermanentID != 4242 {
		t.Errorf("explicit permanent_id ignored, got %d", e.PermanentID)
	}
}

// TestLineForChannel covers the prefix match that decides whether a live
// channel belongs to one of our devices.
func TestLineForChannel(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.Merge(discovered("PJSIP/100", "PJSIP/1001"))

	for _, tc := range []struct {
		channel string
		want    int
	}{
		{"PJSIP/1001-00000042", 1},
		{"PJSIP/100-00000042", 0},
		{"pjsip/1001-0000ffff", 1}, // AMI casing is not guaranteed
		{"PJSIP/1001", 1},
		{"PJSIP/2000-00000001", -1},
		{"SIP/1001-00000001", -1},
		{"", -1},
	} {
		if got := r.LineForChannel(tc.channel); got != tc.want {
			t.Errorf("LineForChannel(%q) = %d, want %d", tc.channel, got, tc.want)
		}
	}
}

// TestLineForChannelWithNestedNames: one endpoint's name extending another's
// used to make the match depend on map iteration order, so calls on
// "sales-2" landed on "sales" about half the time.
func TestLineForChannelWithNestedNames(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.Merge(discovered("PJSIP/sales", "PJSIP/sales-2"))

	// Enough repetitions that a map-order dependency would show.
	for i := 0; i < 200; i++ {
		if got := r.LineForChannel("PJSIP/sales-2-0000001a"); got != 1 {
			t.Fatalf("PJSIP/sales-2-0000001a mapped to line %d, want 1", got)
		}
		if got := r.LineForChannel("PJSIP/sales-0000001b"); got != 0 {
			t.Fatalf("PJSIP/sales-0000001b mapped to line %d, want 0", got)
		}
	}
	// A device that is not a line must not be attributed to the one whose
	// name it extends.
	if got := r.LineForChannel("PJSIP/sales-3-0000001c"); got != -1 {
		t.Errorf("PJSIP/sales-3-0000001c mapped to line %d, want -1", got)
	}
}

// TestConfiguredLineStaysPresent: a lines[] entry discovery never produces
// (another channel driver, a filtered endpoint) is in service on the
// administrator's word. It used to be reported out of service by the first
// scan, and again after every AMI reconnect.
func TestConfiguredLineStaysPresent(t *testing.T) {
	r, _ := Load(filepath.Join(t.TempDir(), "lines.json"))
	r.ApplyConfig(loadCfgLines(t, `[{"channel":"SIP/legacy"}]`))

	present := func(when string) {
		t.Helper()
		if e, _ := r.At(0); !e.Present {
			t.Errorf("configured line reported absent %s", when)
		}
	}
	present("after loading the configuration")
	r.Merge(discovered("PJSIP/1001"))
	present("after a scan that did not include it")
	r.MarkAllAbsent()
	present("after the AMI link dropped")
	if e, _ := r.At(1); e.Present {
		t.Error("a discovered line stayed present after the AMI link dropped")
	}
}

// TestRemovedConfigLineIsNoLongerPinned: deleting a lines[] entry hands the
// device back to discovery, which may then report it gone.
func TestRemovedConfigLineIsNoLongerPinned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lines.json")
	r, _ := Load(path)
	r.ApplyConfig(loadCfgLines(t, `[{"channel":"PJSIP/1001"}]`))
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	r, _ = Load(path)
	r.ApplyConfig(nil)
	if e, _ := r.At(0); e.Source != SourceDiscovered {
		t.Fatalf("source after removal from lines[] = %q, want %q", e.Source, SourceDiscovered)
	}
	r.Merge(discovered("PJSIP/1002"))
	if removed := r.PruneAbsent(); len(removed) != 1 || removed[0].Channel != "PJSIP/1001" {
		t.Errorf("PruneAbsent removed %v, want the unpinned PJSIP/1001", removed)
	}
}
