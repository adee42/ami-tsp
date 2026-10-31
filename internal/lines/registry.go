// Package lines holds the provider's line device registry: the ordered list of
// TAPI line devices, whether they came from configuration or from discovery.
//
// # Why any of this is persisted
//
// The PBX is the source of truth for what devices exist, and it is re-read on
// every startup and continuously thereafter. The registry is not a substitute
// for that. It exists because TAPI identity cannot be derived from a live
// query: TSPI_providerEnumDevices must report a device count before any
// connection exists, device IDs are then handed out by position, and
// applications store their per-line preferences against that position and
// against the permanent line ID. Rebuild the list from scratch each boot and a
// PBX that is briefly unreachable yields no telephony at all, while a single
// endpoint missing mid-reload shifts every device after it onto the wrong
// phone.
//
// # Two kinds of field, two different rules
//
// Identity — Channel, slot and PermanentID — is assigned once and never
// changes. It is the only thing here that cannot be re-derived, and the sole
// reason the file exists. Hence:
//
//   - entries are only ever appended, never removed or moved;
//   - a device that disappears from the PBX keeps its slot and is marked
//     absent (the TSP reports it out of service);
//   - the persisted file, not the configuration, is the authority on order.
//
// Everything else — name, caller ID, dialplan context — is a cache of what the
// PBX said. Live data wins whenever the PBX speaks; the stored copy exists only
// so that enumeration can answer before it has. The distinction that matters in
// Merge: a scan that did not ask about a field reports it empty, and an empty
// field means "not asked", never "cleared". Treating the two as the same is
// what lets a routine rescan quietly downgrade good data.
package lines

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/adee42/ami-tsp/internal/config"
)

// permanentIDBase is where automatically assigned permanent IDs start. It is
// far above the 1-based indices config.Config gives unnumbered manual lines,
// so the two allocation schemes cannot collide.
const permanentIDBase = 10000

// Source records where an entry came from.
const (
	SourceConfig     = "config"
	SourceDiscovered = "discovered"
)

// Entry is one line device.
type Entry struct {
	config.Line

	Source string `json:"source"`

	// Present reports whether the most recent successful scan still saw this
	// device. Absent devices keep their slot; see the package comment.
	Present bool `json:"present"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Registry is the ordered device list. It is safe for concurrent use: the
// monitor reads it from the AMI goroutine while the TSP reads it from TapiSrv
// threads.
type Registry struct {
	path string

	mu      sync.RWMutex
	entries []Entry
	byChan  map[string]int // lower-case channel -> index
	dirty   bool

	// scanned records that a scan has completed in this process, which is what
	// makes Present meaningful. Straight after a load nothing has been
	// confirmed either way, and reporting that as "absent" would misrepresent
	// a PBX we have simply not spoken to yet.
	scanned bool
}

// file is the on-disk shape. The version field exists so that a future change
// to the entry layout can be detected rather than silently misread.
type file struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

const fileVersion = 1

// Load reads the registry from path. A missing file yields an empty registry,
// which is the normal first-run case; a corrupt one is an error, because
// starting over would renumber every device.
func Load(path string) (*Registry, error) {
	r := &Registry{path: path, byChan: map[string]int{}}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("read line registry %s: %w", path, err)
	}
	var f file
	if err := json.Unmarshal(config.TrimBOM(raw), &f); err != nil {
		return nil, fmt.Errorf("parse line registry %s: %w", path, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("line registry %s has version %d, expected %d", path, f.Version, fileVersion)
	}
	for _, e := range f.Entries {
		if e.Channel == "" {
			continue
		}
		e.Line.Normalise()
		// Nothing has been scanned yet in this process.
		e.Present = false
		r.appendLocked(e)
	}
	return r, nil
}

// Scanned reports whether a scan has completed in this process. Until it has,
// each entry's Present flag says nothing.
func (r *Registry) Scanned() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scanned
}

// Len returns the number of line devices.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// Entries returns a copy of the device list, indexed by line index.
func (r *Registry) Entries() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, len(r.entries))
	copy(out, r.entries)
	return out
}

// At returns the entry at a line index. The second result is false if the
// index is out of range.
func (r *Registry) At(i int) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if i < 0 || i >= len(r.entries) {
		return Entry{}, false
	}
	return r.entries[i], true
}

// IndexOfChannel returns the line index for an exact device channel
// ("PJSIP/1001"), or -1.
func (r *Registry) IndexOfChannel(channel string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if i, ok := r.byChan[strings.ToLower(channel)]; ok {
		return i
	}
	return -1
}

// LinesWithExtension returns every line index whose extension matches, so a
// caller can report an ambiguous match rather than silently pick one. Nothing
// stops two devices sharing an extension.
func (r *Registry) LinesWithExtension(ext string) []int {
	ext = strings.TrimSpace(ext)
	if ext == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []int
	for i, e := range r.entries {
		if strings.EqualFold(e.Extension, ext) {
			out = append(out, i)
		}
	}
	return out
}

// LineForChannel maps a live Asterisk channel name to a line index.
//
// Channel names are the device plus a per-call suffix: "PJSIP/1001-00000042".
// The suffix is cut at the *last* "-" and the remainder looked up exactly.
// Matching on a prefix instead is ambiguous as soon as one endpoint's name
// extends another's: "PJSIP/sales-2-0000001a" starts with both "pjsip/sales-"
// and "pjsip/sales-2-", and which one won depended on map iteration order.
func (r *Registry) LineForChannel(channel string) int {
	if channel == "" {
		return -1
	}
	lc := strings.ToLower(channel)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if i, ok := r.byChan[lc]; ok {
		return i
	}
	if cut := strings.LastIndex(lc, "-"); cut > 0 {
		if i, ok := r.byChan[lc[:cut]]; ok {
			return i
		}
	}
	return -1
}

// ApplyConfig overlays the manually configured lines onto the registry. A
// configured line whose channel is already known updates that slot in place;
// one that is not is appended. Configuration never reorders anything.
func (r *Registry) ApplyConfig(cfgLines []config.Line) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	configured := make(map[string]bool, len(cfgLines))
	for _, l := range cfgLines {
		if l.Channel == "" {
			continue
		}
		l.Normalise()
		configured[strings.ToLower(l.Channel)] = true
		if i, ok := r.byChan[strings.ToLower(l.Channel)]; ok {
			e := &r.entries[i]
			// The configured permanent ID wins, but only if one was actually
			// written down: config.Config invents index-based IDs for
			// unnumbered lines, and those must not displace an ID the
			// registry already handed out.
			permID := e.PermanentID
			if l.HasExplicitPermanentID() {
				permID = l.PermanentID
			}
			e.Line = l
			e.Line.PermanentID = permID
			e.Source = SourceConfig
			// A configured line is in service on the administrator's word;
			// no scan confirms or denies it.
			e.Present = true
			r.dirty = true
			continue
		}
		// A manual line imported for the first time keeps the ID config gave
		// it, positional default included. That is what an installation
		// upgrading from a registry-less build already advertises, and the
		// registry pins it from here on.
		e := Entry{Line: l, Source: SourceConfig, Present: true, FirstSeen: now, LastSeen: now}
		if e.PermanentID == 0 {
			e.PermanentID = r.nextPermanentIDLocked()
		}
		r.appendLocked(e)
		r.dirty = true
	}

	// A line whose lines[] entry has been deleted is no longer pinned. It
	// keeps its slot and permanent ID, and from now on discovery decides
	// whether it exists, as for any other device.
	for i := range r.entries {
		e := &r.entries[i]
		if e.Source == SourceConfig && !configured[strings.ToLower(e.Channel)] {
			e.Source = SourceDiscovered
			r.dirty = true
		}
	}
	r.resolvePermanentIDsLocked()
}

// Merge folds a completed discovery scan into the registry. It returns the
// line indices that were newly added and those that were previously present
// and have now gone, so the caller can drive LINE_CREATE and out-of-service
// notifications.
//
// Only entries that this scan could have produced are considered for the gone
// list; a manually configured line is never reported as gone by discovery.
func (r *Registry) Merge(found []Entry) (added, gone []int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	seen := make(map[string]bool, len(found))
	r.scanned = true

	for _, f := range found {
		if f.Channel == "" {
			continue
		}
		f.Channel = strings.TrimRight(f.Channel, "-")
		key := strings.ToLower(f.Channel)
		seen[key] = true

		i, ok := r.byChan[key]
		if !ok {
			// Only a new entry is normalised. Doing it to an update would
			// invent a name and caller ID for fields the scan deliberately
			// left blank, and those inventions would overwrite what is
			// already on file.
			e := f
			e.Line.Normalise()
			e.Source = SourceDiscovered
			e.Present = true
			e.FirstSeen, e.LastSeen = now, now
			e.PermanentID = r.nextPermanentIDLocked()
			r.appendLocked(e)
			added = append(added, len(r.entries)-1)
			r.dirty = true
			continue
		}

		e := &r.entries[i]
		if !e.Present {
			r.dirty = true
		}
		e.Present = true
		e.LastSeen = now
		// A configured line keeps everything the administrator wrote; a
		// discovered one picks up whatever the PBX now reports.
		if e.Source != SourceConfig {
			if f.Name != "" && f.Name != e.Name {
				e.Name = f.Name
				r.dirty = true
			}
			if f.CallerIDName != "" && f.CallerIDName != e.CallerIDName {
				e.CallerIDName = f.CallerIDName
				r.dirty = true
			}
			if f.CallerIDNum != "" && f.CallerIDNum != e.CallerIDNum {
				e.CallerIDNum = f.CallerIDNum
				r.dirty = true
			}
			if f.Context != "" && f.Context != e.Context {
				e.Context = f.Context
				r.dirty = true
			}
		}
	}

	for i := range r.entries {
		e := &r.entries[i]
		if e.Source == SourceConfig || !e.Present {
			continue
		}
		if !seen[strings.ToLower(e.Channel)] {
			e.Present = false
			gone = append(gone, i)
			r.dirty = true
		}
	}
	return added, gone
}

// PruneAbsent removes discovered entries that the last scan did not see, and
// returns them.
//
// This is the one operation that breaks the append-only rule, so it may only
// run at service startup, before TSPI_providerEnumDevices has reported anything
// to TapiSrv — at that moment nothing has been promised and renumbering costs
// nothing in flight. Permanent IDs are left alone: positions move, identities
// do not, so an application that keys on the permanent line ID is unaffected.
//
// Absence has to have been established by an actual scan. Straight after a load
// every entry is marked absent because nothing has been confirmed yet, and
// pruning from that state would erase the registry — so a scan that never ran,
// or a PBX that could not be reached, prunes nothing.
func (r *Registry) PruneAbsent() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.scanned {
		return nil
	}

	var (
		kept    []Entry
		removed []Entry
	)
	for _, e := range r.entries {
		// A configured line is pinned by the administrator having written it
		// down; discovery neither marks it absent nor removes it.
		if e.Present || e.Source == SourceConfig {
			kept = append(kept, e)
			continue
		}
		removed = append(removed, e)
	}
	if len(removed) == 0 {
		return nil
	}

	// byChan holds indices, and every entry after a removal has moved.
	r.entries = kept
	r.byChan = make(map[string]int, len(kept))
	for i, e := range kept {
		r.byChan[strings.ToLower(e.Channel)] = i
	}
	r.dirty = true
	return removed
}

// MarkAllAbsent clears the present flag on every discovered entry. The monitor
// calls it when the AMI link drops: the PBX view is gone, so nothing it
// reported can be claimed to exist until the next scan confirms it.
//
// Configured lines are left alone. Their presence was never the PBX's to
// report, and no scan would ever restore it.
func (r *Registry) MarkAllAbsent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.entries {
		if r.entries[i].Source != SourceConfig {
			r.entries[i].Present = false
		}
	}
}

// Save writes the registry if anything changed since the last write. The write
// is atomic: a half-written registry would renumber devices on the next start.
func (r *Registry) Save() error {
	r.mu.Lock()
	if !r.dirty || r.path == "" {
		r.mu.Unlock()
		return nil
	}
	f := file{Version: fileVersion, Entries: make([]Entry, len(r.entries))}
	copy(f.Entries, r.entries)
	path := r.path
	r.mu.Unlock()

	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encode line registry: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}

	r.mu.Lock()
	r.dirty = false
	r.mu.Unlock()
	return nil
}

// appendLocked adds an entry to the end of the list. Caller holds mu.
func (r *Registry) appendLocked(e Entry) {
	key := strings.ToLower(e.Channel)
	if _, exists := r.byChan[key]; exists {
		return
	}
	r.entries = append(r.entries, e)
	r.byChan[key] = len(r.entries) - 1
}

// nextPermanentIDLocked allocates an unused permanent ID. Caller holds mu.
func (r *Registry) nextPermanentIDLocked() uint32 {
	next := uint32(permanentIDBase)
	for _, e := range r.entries {
		if e.PermanentID >= next {
			next = e.PermanentID + 1
		}
	}
	return next
}

// resolvePermanentIDsLocked repairs missing or duplicated permanent IDs, which
// a hand-edited configuration can introduce. The earlier entry keeps the ID:
// it is the one applications have already seen. Caller holds mu.
func (r *Registry) resolvePermanentIDsLocked() {
	seen := map[uint32]bool{}
	for i := range r.entries {
		e := &r.entries[i]
		if e.PermanentID != 0 && !seen[e.PermanentID] {
			seen[e.PermanentID] = true
			continue
		}
		id := r.nextPermanentIDLocked()
		for seen[id] {
			id++
		}
		e.PermanentID = id
		seen[id] = true
		r.dirty = true
	}
}
