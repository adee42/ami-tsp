// Command amitsp-ctl installs, removes and diagnoses the AMI telephony
// service provider.
//
// It must be built as a 64-bit binary: TapiSrv is 64-bit on 64-bit Windows,
// so provider registration has to happen through the 64-bit tapi32.dll.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/adee42/ami-tsp/internal/config"
	"github.com/adee42/ami-tsp/internal/lines"
	"github.com/adee42/ami-tsp/internal/logx"
	"github.com/adee42/ami-tsp/internal/pbx"
)

const usage = `amitsp-ctl - AMI TAPI service provider control

Usage:
  amitsp-ctl config                 validate and print the resolved configuration
  amitsp-ctl discover [--refresh]   scan the PBX and show which endpoints become lines
                                    --refresh re-reads names and contexts for known lines
  amitsp-ctl registry [--probe]     print the line device registry
                                    --probe first re-scans the PBX, as startup does
  amitsp-ctl dialplan [context]     list dialplan contexts, or one context's extensions
  amitsp-ctl test [seconds]         connect to AMI and print call events (default 60s)
  amitsp-ctl dial <from> <number>   place a test call through AMI (no TAPI involved)
                                    <from> is the calling extension, or #<n> for a line index
  amitsp-ctl install <path\amitsp.dll>
                                    install the provider into System32 as amitsp.tsp,
                                    alongside amitspui.dll, and register it
  amitsp-ctl remove <providerID>    unregister a provider
  amitsp-ctl list                   list registered TAPI providers
  amitsp-ctl lines [-v] [--api <hex version>]
                                    list TAPI line devices visible to applications
                                    -v prints the full LINEDEVCAPS/LINEADDRESSCAPS
                                    an application filters on, --api enumerates at a
                                    given TAPI version (default 0x00020002)

install and remove change machine state and require an elevated prompt.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	switch strings.ToLower(os.Args[1]) {
	case "config":
		err = cmdConfig()
	case "discover":
		err = cmdDiscover(os.Args[2:])
	case "registry":
		err = cmdRegistry(os.Args[2:])
	case "dialplan":
		err = cmdDialplan(os.Args[2:])
	case "test":
		err = cmdTest(os.Args[2:])
	case "dial":
		err = cmdDial(os.Args[2:])
	case "install":
		err = cmdInstall(os.Args[2:])
	case "remove":
		err = cmdRemove(os.Args[2:])
	case "list":
		err = cmdList()
	case "lines":
		err = cmdLines(os.Args[2:])
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// consoleLog sends the library log to stderr instead of the provider's log
// file, so a diagnostic run shows AMI failures as they happen. Set
// AMITSP_DEBUG for the full protocol trace.
func consoleLog() {
	level := logx.LevelInfo
	if os.Getenv("AMITSP_DEBUG") != "" {
		level = logx.LevelDebug
	}
	logx.Configure("-", level)
}

func loadCfg() (*config.Config, error) {
	path := config.Path()
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	fmt.Printf("configuration: %s\n", path)
	return cfg, nil
}

func cmdConfig() error {
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	// Show the effective configuration after defaults are applied, with the
	// secret withheld.
	shown := *cfg
	if shown.AMI.Secret != "" {
		shown.AMI.Secret = "***"
	}
	out, _ := json.MarshalIndent(shown, "", "  ")
	fmt.Println(string(out))
	fmt.Printf("\nlog file:      %s\n", cfg.Log.File)
	fmt.Printf("line registry: %s\n", config.RegistryPath())
	return nil
}

// cmdRegistry prints the device list as the provider would enumerate it. The
// line index is what TAPI device IDs are derived from and what `dial` takes,
// so it is the first column.
//
// With --probe it runs the same startup scan TSPI_providerEnumDevices does,
// which is the only way to exercise that path without installing the DLL and
// restarting the Telephony service.
func cmdRegistry(args []string) error {
	probe := len(args) > 0 && strings.EqualFold(args[0], "--probe")

	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	if probe {
		// --probe reproduces startup, and startup removes devices the PBX no
		// longer has. Say so before doing it, not after.
		consoleLog()
		fmt.Println("re-scanning the PBX as startup does; devices it no longer has will be removed")
	}
	started := time.Now()
	reg, err := pbx.BuildRegistry(cfg, probe)
	if err != nil {
		return err
	}
	if probe {
		fmt.Printf("\nenumerated in %s\n", time.Since(started).Round(time.Millisecond))
	}
	printRegistry(reg)
	return nil
}

func printRegistry(reg *lines.Registry) {
	entries := reg.Entries()
	if len(entries) == 0 {
		fmt.Println("no line devices known yet; run `amitsp-ctl discover`")
		return
	}
	fmt.Printf("%d line device(s)\n\n", len(entries))
	fmt.Printf("%-4s %-10s %-24s %-9s %-8s %-24s %s\n",
		"IDX", "PERM.ID", "CHANNEL", "SOURCE", "PRESENT", "DIAL CONTEXT", "NAME")
	for i, e := range entries {
		// Without a scan in this process, Present is not evidence of anything;
		// "?" says so rather than implying every phone has gone away.
		present := "?"
		if reg.Scanned() {
			present = "no"
			if e.Present {
				present = "yes"
			}
		}
		// An empty context means outbound calls fall back to dialplan.context,
		// which is exactly the case that produces "Extension does not exist".
		dialCtx := e.Context
		if dialCtx == "" {
			dialCtx = "(dialplan.context)"
		}
		fmt.Printf("%-4d %-10d %-24s %-9s %-8s %-24s %s\n",
			i, e.PermanentID, e.Channel, e.Source, present, dialCtx, e.Name)
	}
}

// cmdDialplan answers the question an Originate failure raises: which context
// does this PBX actually put calls in? With no argument it summarises the
// contexts; with one it lists that context's extensions.
func cmdDialplan(args []string) error {
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	consoleLog()

	var want string
	if len(args) > 0 {
		want = args[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(cfg.AMI.ConnectTimeoutSec+cfg.AMI.ActionTimeoutSec*2)*time.Second)
	defer cancel()

	entries, err := pbx.ShowDialplan(ctx, cfg, want)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		if want != "" {
			return fmt.Errorf("context %q has no extensions (does it exist?)", want)
		}
		return fmt.Errorf("the PBX reported no dialplan; does the manager account have read=dialplan?")
	}

	if want == "" {
		// Summarise: the point is to recognise the right context by name.
		counts := map[string]int{}
		var order []string
		for _, e := range entries {
			if _, seen := counts[e.Context]; !seen {
				order = append(order, e.Context)
			}
			counts[e.Context]++
		}
		sort.Strings(order)
		fmt.Printf("\n%d context(s); dialplan.context must name one of these\n\n", len(order))
		fmt.Printf("%-40s %s\n", "CONTEXT", "ENTRIES")
		for _, c := range order {
			fmt.Printf("%-40s %d\n", c, counts[c])
		}
		fmt.Println("\nrun `amitsp-ctl dialplan <context>` to see what a context can reach")
		return nil
	}

	var extens, includes []pbx.DialplanEntry
	for _, e := range entries {
		if e.IsInclude() {
			includes = append(includes, e)
		} else {
			extens = append(extens, e)
		}
	}

	fmt.Printf("\n%s: %d extension(s), %d include(s)\n", want, len(extens), len(includes))
	if len(extens) > 0 {
		fmt.Printf("\n%-24s %-10s %s\n", "EXTENSION", "PRIORITY", "APPLICATION")
		for _, e := range extens {
			fmt.Printf("%-24s %-10s %s\n", e.Extension, e.Priority, e.App)
		}
	}
	if len(includes) > 0 {
		// A context of pure includes still reaches everything they hold:
		// Asterisk follows includes when it decides whether an Originate's
		// extension exists.
		fmt.Println("\nincludes (their extensions are reachable from here too):")
		for _, e := range includes {
			fmt.Printf("  %s\n", e.Includes)
		}
	}
	return nil
}

// cmdDiscover answers the question discovery actually gets asked: why is this
// phone not in my line list?
func cmdDiscover(args []string) error {
	refresh := len(args) > 0 && strings.EqualFold(args[0], "--refresh")

	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	consoleLog()

	if !cfg.Discovery.IsEnabled() {
		fmt.Println("note: discovery is disabled in the configuration; scanning anyway")
	}

	reg, err := pbx.BuildRegistry(cfg, false)
	if err != nil {
		return err
	}

	timeout := time.Duration(cfg.Discovery.InitialTimeoutSec+cfg.AMI.ActionTimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	found, rejected, err := pbx.DiscoverOnce(ctx, cfg, reg, refresh)
	if err != nil {
		return err
	}

	fmt.Printf("\n%d endpoint(s) would be exported:\n", len(found))
	for _, e := range found {
		status, name := "new", e.Name
		if i := reg.IndexOfChannel(e.Channel); i >= 0 {
			status = "known"
			// A rescan leaves the name blank for endpoints it did not
			// re-query; show what is on file rather than nothing.
			if known, ok := reg.At(i); ok && name == "" {
				name = known.Name
			}
		}
		fmt.Printf("  %-24s %-6s %s\n", e.Channel, status, name)
	}
	if len(rejected) > 0 {
		fmt.Printf("\n%d endpoint(s) skipped:\n", len(rejected))
		for _, r := range rejected {
			fmt.Printf("  %-24s %s\n", r.Endpoint, r.Reason)
		}
	}

	added, gone := reg.Merge(found)
	// Save unconditionally; a scan can learn an endpoint's dialplan context
	// without adding or removing any device. Save no-ops when nothing changed.
	if err := reg.Save(); err != nil {
		return err
	}
	if len(added) > 0 || len(gone) > 0 {
		fmt.Printf("\nregistry updated: %d added, %d marked gone\n", len(added), len(gone))
	}
	fmt.Println()
	printRegistry(reg)
	return nil
}

func cmdTest(args []string) error {
	seconds := 60
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("bad duration %q", args[0])
		}
		seconds = n
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	consoleLog()

	reg, err := pbx.BuildRegistry(cfg, false)
	if err != nil {
		return err
	}
	mon := pbx.NewMonitor(cfg, reg)
	mon.Start()
	defer mon.Stop()

	fmt.Printf("watching %d line(s) for %ds; Ctrl+C to stop\n", reg.Len(), seconds)
	for i, e := range reg.Entries() {
		fmt.Printf("  [%d] %-24s %s\n", i, e.Channel, e.Name)
	}
	fmt.Println()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	deadline := time.After(time.Duration(seconds) * time.Second)

	for {
		select {
		case <-sig:
			return nil
		case <-deadline:
			return nil
		case ev, ok := <-mon.Events():
			if !ok {
				return nil
			}
			printEvent(reg, ev)
		}
	}
}

func printEvent(reg *lines.Registry, ev pbx.Event) {
	ts := time.Now().Format("15:04:05.000")
	channel := "?"
	if e, ok := reg.At(ev.LineIndex); ok {
		channel = e.Channel
	}
	switch ev.Type {
	case pbx.EventLink:
		fmt.Printf("%s  LINK      %s\n", ts, map[bool]string{true: "up", false: "down"}[ev.Up])
		return
	case pbx.EventLineAdded:
		fmt.Printf("%s  LINE+ %-20s discovered as line %d\n", ts, channel, ev.LineIndex)
		return
	case pbx.EventLineState:
		fmt.Printf("%s  LINE  %-20s %s\n", ts, channel,
			map[bool]string{true: "in service", false: "out of service"}[ev.Up])
		return
	}
	c := ev.Call
	if c == nil {
		return
	}
	name := channel
	kind := map[pbx.EventType]string{
		pbx.EventCallNew:   "NEW  ",
		pbx.EventCallState: "STATE",
		pbx.EventCallInfo:  "INFO ",
		pbx.EventCallEnd:   "END  ",
	}[ev.Type]
	dir := "out"
	if c.Inbound {
		dir = "in "
	}
	fmt.Printf("%s  %s %-20s %s %-10s remote=%s %s\n",
		ts, kind, name, dir, c.State, c.RemoteNumber, c.RemoteName)
}

func cmdDial(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: amitsp-ctl dial <extension>|#<line> <number>")
	}
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	consoleLog()

	reg, err := pbx.BuildRegistry(cfg, false)
	if err != nil {
		return err
	}
	idx, err := resolveLine(reg, args[0])
	if err != nil {
		return err
	}
	if e, ok := reg.At(idx); ok {
		fmt.Printf("calling from line %d, %s (%s)\n", idx, e.Extension, e.Channel)
	}

	mon := pbx.NewMonitor(cfg, reg)
	mon.Start()
	defer mon.Stop()

	// Give the client a moment to connect and log in.
	for i := 0; i < 50 && !mon.Connected(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if !mon.Connected() {
		return fmt.Errorf("AMI not connected")
	}

	tag := pbx.NewTag()
	if err := mon.Originate(idx, args[1], tag); err != nil {
		return err
	}
	fmt.Printf("originated (key %s); watching for 30s\n", tag)

	deadline := time.After(30 * time.Second)
	for {
		select {
		case <-deadline:
			return nil
		case ev, ok := <-mon.Events():
			if !ok {
				return nil
			}
			printEvent(reg, ev)
		}
	}
}

// resolveLine turns the first argument of `dial` into a line index.
//
// The everyday form is the extension the phone answers on, because that is
// what is written on the handset. A "#" prefix selects a line by its index
// instead, for the cases the extension cannot express: two devices sharing an
// extension, or a line whose extension is not what you would type.
func resolveLine(reg *lines.Registry, spec string) (int, error) {
	spec = strings.TrimSpace(spec)

	if strings.HasPrefix(spec, "#") {
		idx, err := strconv.Atoi(strings.TrimSpace(spec[1:]))
		if err != nil {
			return 0, fmt.Errorf("bad line index %q", spec)
		}
		if idx < 0 || idx >= reg.Len() {
			return 0, fmt.Errorf("line index %d out of range (0..%d)\n%s", idx, reg.Len()-1, knownLines(reg))
		}
		return idx, nil
	}

	switch matches := reg.LinesWithExtension(spec); len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return 0, fmt.Errorf("no line has extension %q\n%s", spec, knownLines(reg))
	default:
		var where []string
		for _, i := range matches {
			e, _ := reg.At(i)
			where = append(where, fmt.Sprintf("#%d (%s)", i, e.Channel))
		}
		return 0, fmt.Errorf("extension %q is on %d lines: %s; select one with its # index",
			spec, len(matches), strings.Join(where, ", "))
	}
}

// knownLines renders the choices for an error message, so a failed lookup does
// not send the reader off to another command.
func knownLines(reg *lines.Registry) string {
	entries := reg.Entries()
	if len(entries) == 0 {
		return "no lines are known yet; run `amitsp-ctl discover`"
	}
	var b strings.Builder
	b.WriteString("known lines:")
	for i, e := range entries {
		fmt.Fprintf(&b, "\n  %-6s #%-3d %-24s %s", e.Extension, i, e.Channel, e.Name)
	}
	return b.String()
}

// ------------------------------------------------------- TAPI registration

var (
	tapi32                   = syscall.NewLazyDLL("tapi32.dll")
	procLineAddProviderW     = tapi32.NewProc("lineAddProviderW")
	procLineRemoveProvider   = tapi32.NewProc("lineRemoveProvider")
	procLineGetProviderListW = tapi32.NewProc("lineGetProviderListW")
	procLineInitializeExW    = tapi32.NewProc("lineInitializeExW")
	procLineShutdown         = tapi32.NewProc("lineShutdown")
	procLineNegotiateAPIVers = tapi32.NewProc("lineNegotiateAPIVersion")
	procLineGetDevCapsW      = tapi32.NewProc("lineGetDevCapsW")
	procLineGetAddressCapsW  = tapi32.NewProc("lineGetAddressCapsW")
)

const tapiVersion = 0x00020002

// providerFileName is the name the provider is installed and registered under.
//
// TAPI service providers are conventionally named .tsp, as every provider
// Windows ships is (unimdm.tsp, kmddsp.tsp, hidphone.tsp). The extension has
// no technical meaning -- TapiSrv calls LoadLibrary on it either way -- but at
// least one telephony application filters the lines it offers by the driver
// file name, so following the convention is what gets the lines seen.
const providerFileName = "amitsp.tsp"

// legacyProviderFileName is what builds before the rename installed. It is
// only used to recognise, and refuse to duplicate, an older registration.
const legacyProviderFileName = "amitsp.dll"

// uiDLLName must match the name TSPI_providerUIIdentify reports; see
// amitsp_ui_path in tsp/shim.c. It stays a plain .dll: it is loaded by the
// application, not by TapiSrv, and is not itself a service provider.
const uiDLLName = "amitspui.dll"

// copyInto copies a file to dst unless both are already the same path, which
// is the case when installing from System32 itself.
func copyInto(src, dst string) error {
	if strings.EqualFold(src, dst) {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("copy to %s (elevated prompt required?): %w", dst, err)
	}
	fmt.Printf("copied %s -> %s\n", src, dst)
	return nil
}

func cmdInstall(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf(`usage: amitsp-ctl install <path\amitsp.dll>`)
	}
	src, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	// TapiSrv loads providers by bare filename from the system directory. The
	// build produces amitsp.dll; it is installed under the conventional .tsp
	// name, which is what gets registered and what applications see.
	sysDir := filepath.Join(os.Getenv("SystemRoot"), "System32")
	dst := filepath.Join(sysDir, providerFileName)
	if err := copyInto(src, dst); err != nil {
		return err
	}

	// TSPI_providerUIIdentify points TAPI at amitspui.dll beside the provider,
	// and the process calling lineAddProvider loads it from there. Without it
	// the install fails in the client rather than in TapiSrv, so place it
	// first and say so plainly if it is missing from the build.
	uiSrc := filepath.Join(filepath.Dir(src), uiDLLName)
	if _, err := os.Stat(uiSrc); err != nil {
		return fmt.Errorf("UI DLL not found next to the provider: %s (run build.ps1 to produce it)", uiSrc)
	}
	if err := copyInto(uiSrc, filepath.Join(sysDir, uiDLLName)); err != nil {
		return err
	}

	// lineAddProvider happily registers the same file twice, which leaves
	// TapiSrv loading two copies of the provider and is easy to do when
	// reinstalling after a fix.
	if entries, err := providerList(); err == nil {
		for _, e := range entries {
			if strings.EqualFold(e.FileName, providerFileName) {
				fmt.Printf("already registered as provider ID %d; the files above are updated\n", e.ID)
				fmt.Println("restart the Telephony service to load them: net stop tapisrv && net start tapisrv")
				return nil
			}
		}
		// An installation from before the rename is registered under the old
		// name. Registering the new one alongside it would give TapiSrv two
		// copies of the same provider, each enumerating the same lines, so
		// this has to be the administrator's decision rather than a surprise.
		for _, e := range entries {
			if strings.EqualFold(e.FileName, legacyProviderFileName) {
				return fmt.Errorf(
					"provider %s is still registered as ID %d from an earlier install;\n"+
						"remove it first, then install again:\n"+
						"  amitsp-ctl remove %d\n"+
						"(%s can be deleted afterwards; %s replaces it)",
					legacyProviderFileName, e.ID, e.ID,
					filepath.Join(sysDir, legacyProviderFileName), providerFileName)
			}
		}
	}

	name, err := syscall.UTF16PtrFromString(providerFileName)
	if err != nil {
		return err
	}
	var providerID uint32
	ret, _, _ := procLineAddProviderW.Call(
		uintptr(unsafe.Pointer(name)),
		0, // hwndOwner
		uintptr(unsafe.Pointer(&providerID)),
	)
	if r := int32(ret); r != 0 {
		return fmt.Errorf("lineAddProvider failed: %s", tapiError(r))
	}
	fmt.Printf("registered %s as permanent provider ID %d\n", providerFileName, providerID)
	fmt.Println("restart the Telephony service to load it: net stop tapisrv && net start tapisrv")
	return nil
}

func cmdRemove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: amitsp-ctl remove <providerID>")
	}
	id, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("bad provider ID %q", args[0])
	}
	ret, _, _ := procLineRemoveProvider.Call(uintptr(uint32(id)), 0)
	if r := int32(ret); r != 0 {
		return fmt.Errorf("lineRemoveProvider failed: %s", tapiError(r))
	}
	fmt.Printf("removed provider %d\n", id)
	return nil
}

// providerEntry is one registered TAPI service provider.
type providerEntry struct {
	ID       uint32
	FileName string
}

// providerList reads the registered providers from TapiSrv.
func providerList() ([]providerEntry, error) {
	// LINEPROVIDERLIST: 6 DWORDs followed by a variable region holding
	// LINEPROVIDERENTRY records (3 DWORDs each) and the filename strings.
	buf := make([]byte, 16*1024)
	putU32(buf, 0, uint32(len(buf)))
	ret, _, _ := procLineGetProviderListW.Call(tapiVersion, uintptr(unsafe.Pointer(&buf[0])))
	if r := int32(ret); r != 0 {
		return nil, fmt.Errorf("lineGetProviderList failed: %s", tapiError(r))
	}
	num := getU32(buf, 12)
	listOff := getU32(buf, 20)
	out := make([]providerEntry, 0, num)
	for i := uint32(0); i < num; i++ {
		base := listOff + i*12
		out = append(out, providerEntry{
			ID:       getU32(buf, base),
			FileName: utf16At(buf, getU32(buf, base+8), getU32(buf, base+4)),
		})
	}
	return out, nil
}

func cmdList() error {
	entries, err := providerList()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("no TAPI providers registered")
		return nil
	}
	fmt.Printf("%-6s %s\n", "ID", "FILENAME")
	for _, e := range entries {
		fmt.Printf("%-6d %s\n", e.ID, e.FileName)
	}
	return nil
}

// cmdLines exercises the client side of TAPI, which is the quickest way to
// confirm that TapiSrv actually loaded the provider and that it reports the
// configured lines.
//
// -v prints the whole of LINEDEVCAPS and LINEADDRESSCAPS. When an application
// enumerates the lines but offers none of them to its user, it is filtering on
// a field in there, and this is the same view it gets.
//
// --api runs the enumeration at a given TAPI version. An application whose
// minimum is above what this provider negotiates (TSPI 2.2) silently sees no
// lines at all, and `lines --api 0x00030000` is the direct test for that.
func cmdLines(args []string) error {
	verbose := false
	wantAPI := uint32(tapiVersion)
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "-v", "--verbose":
			verbose = true
		case "--api":
			if i+1 >= len(args) {
				return fmt.Errorf("--api needs a version, e.g. --api 0x00030000")
			}
			i++
			v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(args[i]), "0x"), 16, 32)
			if err != nil {
				return fmt.Errorf("bad --api version %q: %w", args[i], err)
			}
			wantAPI = uint32(v)
		default:
			return fmt.Errorf("usage: amitsp-ctl lines [-v] [--api <hex version>]")
		}
	}

	type initParams struct {
		TotalSize, NeededSize, UsedSize, Options uint32
		Handle                                   uintptr
		CompletionKey                            uint32
		_                                        uint32
	}
	params := initParams{Options: 2 /* LINEINITIALIZEEXOPTION_USEEVENT */}
	params.TotalSize = uint32(unsafe.Sizeof(params))

	appName, _ := syscall.UTF16PtrFromString("amitsp-ctl")
	var hLineApp uintptr
	var numDevs uint32
	apiVersion := wantAPI

	ret, _, _ := procLineInitializeExW.Call(
		uintptr(unsafe.Pointer(&hLineApp)),
		0, 0,
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(&numDevs)),
		uintptr(unsafe.Pointer(&apiVersion)),
		uintptr(unsafe.Pointer(&params)),
	)
	if r := int32(ret); r != 0 {
		return fmt.Errorf("lineInitializeEx failed: %s", tapiError(r))
	}
	defer procLineShutdown.Call(hLineApp)

	fmt.Printf("%d TAPI line device(s), requested API 0x%08X, TAPI offers 0x%08X\n\n",
		numDevs, wantAPI, apiVersion)
	if !verbose {
		fmt.Printf("%-4s %-10s %-34s %s\n", "DEV", "PERM.ID", "LINE NAME", "PROVIDER")
	}

	for dev := uint32(0); dev < numDevs; dev++ {
		var version, extID [4]uint32
		ret, _, _ := procLineNegotiateAPIVers.Call(
			hLineApp, uintptr(dev), 0x00010004, uintptr(wantAPI),
			uintptr(unsafe.Pointer(&version[0])), uintptr(unsafe.Pointer(&extID[0])),
		)
		if r := int32(ret); r != 0 {
			// Silently skipping this is exactly what an application does, and
			// is the failure most often mistaken for "the lines are missing".
			fmt.Printf("%-4d version negotiation failed: %s\n", dev, tapiError(r))
			continue
		}
		buf := make([]byte, 16*1024)
		putU32(buf, 0, uint32(len(buf)))
		ret, _, _ = procLineGetDevCapsW.Call(
			hLineApp, uintptr(dev), uintptr(version[0]), 0,
			uintptr(unsafe.Pointer(&buf[0])),
		)
		if r := int32(ret); r != 0 {
			fmt.Printf("%-4d lineGetDevCaps failed: %s\n", dev, tapiError(r))
			continue
		}

		if !verbose {
			// Fixed-header offsets of LINEDEVCAPS; see caps.go.
			provider := utf16At(buf, getU32(buf, dcProviderInfoOffset), getU32(buf, dcProviderInfoSize))
			permID := getU32(buf, dcPermanentLineID)
			lineName := utf16At(buf, getU32(buf, dcLineNameOffset), getU32(buf, dcLineNameSize))
			fmt.Printf("%-4d %-10d %-34s %s\n", dev, permID, lineName, provider)
			continue
		}

		fmt.Printf("device %d  (negotiated API 0x%08X)\n", dev, version[0])
		dumpLineDevCaps(buf)

		acBuf := make([]byte, 16*1024)
		putU32(acBuf, 0, uint32(len(acBuf)))
		ret, _, _ = procLineGetAddressCapsW.Call(
			hLineApp, uintptr(dev), 0, uintptr(version[0]), 0,
			uintptr(unsafe.Pointer(&acBuf[0])),
		)
		if r := int32(ret); r != 0 {
			fmt.Printf("  lineGetAddressCaps failed: %s\n", tapiError(r))
		} else {
			dumpAddressCaps(acBuf)
		}
		fmt.Println()
	}
	return nil
}

// ------------------------------------------------------------------ utils

func putU32(b []byte, off uint32, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func getU32(b []byte, off uint32) uint32 {
	if int(off)+4 > len(b) {
		return 0
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// utf16At decodes a counted UTF-16 string embedded in a TAPI structure.
// size is in bytes and may or may not include the terminating NUL.
func utf16At(b []byte, off, size uint32) string {
	if size == 0 || int(off)+int(size) > len(b) {
		return ""
	}
	u := make([]uint16, 0, size/2)
	for i := uint32(0); i+1 < size; i += 2 {
		c := uint16(b[off+i]) | uint16(b[off+i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return syscall.UTF16ToString(u)
}

// lineErrNames maps the LINEERR_* values from tapi.h to their names. Only the
// codes TAPI can plausibly return to this tool are listed; anything else is
// reported numerically.
var lineErrNames = map[uint32]string{
	0x80000002: "LINEERR_BADDEVICEID",
	0x8000000C: "LINEERR_INCOMPATIBLEAPIVERSION",
	0x8000000E: "LINEERR_INIFILECORRUPT",
	0x8000000F: "LINEERR_INUSE",
	0x80000014: "LINEERR_INVALAPPHANDLE",
	0x80000015: "LINEERR_INVALAPPNAME",
	0x80000024: "LINEERR_INVALDEVICEHANDLE",
	0x80000032: "LINEERR_INVALPARAM",
	0x80000035: "LINEERR_INVALPOINTER",
	0x80000042: "LINEERR_NODEVICE",
	0x80000043: "LINEERR_NODRIVER",
	0x80000044: "LINEERR_NOMEM",
	0x80000047: "LINEERR_NOTREGISTERED",
	0x80000048: "LINEERR_OPERATIONFAILED",
	0x80000049: "LINEERR_OPERATIONUNAVAIL",
	0x8000004B: "LINEERR_RESOURCEUNAVAIL",
	0x8000004D: "LINEERR_STRUCTURETOOSMALL",
	0x80000050: "LINEERR_UNINITIALIZED",
	0x80000052: "LINEERR_REINIT",
	0x80000056: "LINEERR_NOMULTIPLEINSTANCE",
}

// lineErrHints explains the codes whose name alone does not point at a cause.
// These are the ones that actually come up while registering a provider.
var lineErrHints = map[uint32]string{
	0x80000049: "the provider does not export TSPI_providerUIIdentify, so TAPI has no TUISPI_providerInstall to call",
	0x80000048: "TapiSrv could not load the DLL: check it is 64-bit and that every imported DLL resolves",
	0x80000043: "the file is not a TAPI service provider, or a required TSPI_* export is missing",
	0x80000056: "the provider is already registered; remove it first",
	0x8000000E: "the Telephony registry keys are inconsistent",
}

// tapiError renders a LINEERR_* return value with its name and, where one is
// known, the cause behind it.
func tapiError(code int32) string {
	v := uint32(code)
	msg := fmt.Sprintf("LINEERR 0x%08X", v)
	if name, ok := lineErrNames[v]; ok {
		msg = name + fmt.Sprintf(" (0x%08X)", v)
	}
	if hint, ok := lineErrHints[v]; ok {
		msg += ": " + hint
	}
	if !isElevated() {
		msg += " [not running elevated?]"
	}
	return msg
}

// isElevated reports whether the process can write to System32, which is a
// good enough proxy for "running as administrator" here.
func isElevated() bool {
	probe := filepath.Join(os.Getenv("SystemRoot"), "System32", ".amitsp-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(probe)
	return true
}
