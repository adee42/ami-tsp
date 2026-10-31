# ami-tsp — a Windows TAPI service provider for Asterisk (AMI)

A TAPI 2.2 Telephony Service Provider, written in Go, that presents Asterisk
extensions as Windows TAPI line devices. Any TAPI-aware application (CRM
dialler, Windows Phone Dialer, ERP click-to-dial) gets third-party call
control and screen-pop against an Asterisk PBX over the Manager Interface.
Asterisk-based appliances that expose AMI work the same way; see
[Yeastar S-Series and P-Series](#yeastar-s-series-and-p-series).

**Download:** ready-built binaries are on the
[releases page](https://github.com/adee42/ami-tsp/releases/latest); see
[Download](#download).

```
 TAPI application  ──tapi32.dll──▶  TapiSrv (svchost)  ──▶  amitsp.tsp  ──TCP/AMI──▶  Asterisk
   (32 or 64 bit)                     (64-bit)              (this project)
```

## What works

| TAPI operation | AMI mechanism | Notes |
|---|---|---|
| Line device list | `PJSIPShowEndpoints` | Endpoints become line devices by themselves; rescanned periodically |
| `lineMakeCall` | `Originate` to the device, dialplan dials the destination | Uniqueid preset via `ChannelId` for immediate correlation |
| `lineDrop` | `Hangup` | |
| `lineBlindTransfer`, `lineRedirect` | `Redirect` | Into the line's dialplan context, as for `lineMakeCall` |
| `lineGenerateDigits` | `PlayDTMF` | One action per digit |
| Inbound call notification (screen pop) | `Newchannel` / `DialBegin` / `Newstate` | Caller ID from the calling leg |
| Outbound call notification | `Newchannel` (channel born off-hook) | The call appears on the calling line as soon as the handset is lifted |
| Destination while dialling | `NewExten`, `DialBegin` | See the note below on what Asterisk can actually see |
| Call state tracking | `Newstate`, `DialEnd`, `Hold`/`Unhold`, `Hangup` | Mapped to `LINECALLSTATE_*` |
| Connected-party updates | `NewConnectedLine`, `NewCallerid` | Keeps the display right after a transfer |
| Line in/out of service | AMI link state | `LINEDEVSTATE_INSERVICE` / `OUTOFSERVICE` |
| Hangup cause | `Cause` (Q.850) | Mapped to `LINEDISCONNECTMODE_*` (busy, no answer, rejected …) |

## What does not, and why

**`lineAnswer` and `lineHold` are not natively possible over AMI.** AMI is a
third-party call control interface: it can create, destroy and re-route
channels, but it cannot reach into a SIP phone and make it go off-hook or put
its own call on hold. Those are first-party operations that belong to the
device.

The workaround this provider implements is a SIP `NOTIFY` (`Event: talk` /
`Event: hold`), which Snom, Yealink and Grandstream phones honour when
configured to. It is opt-in per line via `answer_mode` / `hold_mode`, and
when it is off the provider reports `LINEERR_OPERATIONUNAVAIL` **and** clears
the matching `LINECALLFEATURE_*` bit, so applications grey the button out
rather than offering something that silently fails.

**There is no per-digit dialling state.** A SIP phone collects the whole number
itself and sends it in one INVITE, so Asterisk never sees a partial number:
the destination arrives complete, and the provider reports it once via
`NewExten` / `DialBegin` rather than growing digit by digit. Both legs of an
internal call are tracked, so the calling phone reports `DIALING` at off-hook,
`PROCEEDING` once the destination resolves, and `RINGBACK` while the called
phone rings — the last of these is inferred from the *called* leg's state,
because a calling channel does not change state while it waits.

Also not implemented, deliberately:

- **Consultation transfer / conference** (`lineSetupTransfer`,
  `lineCompleteTransfer`, `lineSetupConference`). Asterisk's `Atxfer` is
  available but its state model does not map cleanly onto TAPI's
  consultation-call semantics; blind transfer covers the common case.
- **Media access** (`lineMonitorDigits`, `lineMonitorMedia`, wave devices).
  AMI carries signalling only; there is no audio stream to hand to Windows.
- **`lineMakeCall` with a null address** (go off-hook and wait for digits).
  There is no AMI primitive for it.

## Requirements

- **64-bit Windows.** TapiSrv is 64-bit and loads providers in-process, so
  the DLL must be 64-bit. 32-bit TAPI applications still work — they talk to
  the 64-bit TapiSrv over RPC. A 32-bit build is not possible: cgo exports
  cdecl on 386, TSPI requires stdcall.
- **Go 1.22+** and an **x86_64 mingw-w64 gcc** to build. Built and verified
  here with Go 1.26.5 and WinLibs GCC 16.1.0 (UCRT):
  `winget install GoLang.Go BrechtSanders.WinLibs.POSIX.UCRT`. The resulting
  DLL imports only `KERNEL32.dll` and the UCRT `api-ms-win-crt-*` stubs, so
  there is no mingw runtime to deploy alongside it.
  If your workstation enforces AppLocker or Software Restriction Policies,
  both `gcc.exe` and the build output directory need to be executable, or
  the build fails with "blocked by group policy".
- **Asterisk 12 or newer** for the `ChannelId` originate header and the
  `DialBegin`/`DialEnd` events. Older versions fall back to a channel
  variable for correlation but will report less accurate direction.

### manager.conf

```ini
[tapi]
secret = change-me
deny   = 0.0.0.0/0.0.0.0
permit = 10.1.2.0/255.255.255.0
read   = system,call,dialplan,reporting
write  = system,call,originate
```

`read=call` supplies the channel events; `write=originate` and `write=call`
are needed for Originate, Hangup, Redirect and PlayDTMF. `read=system` (or
`reporting`, depending on the Asterisk version) is what lets
`PJSIPShowEndpoints` answer — without it discovery finds nothing and the log
says the action was denied. It also lets `CoreShowChannels` answer, which the
provider uses to resynchronise its calls with the PBX (see below).

`write=system` lets the provider install an **event filter** (the `Filter`
action) right after login, so Asterisk only sends the sixteen kinds of event
it uses. Without it the manager session carries everything the account may read
— every `VarSet` of the dialplan, RTCP reports for every media stream, CDR and
CEL records — and on a busy PBX that is most of the traffic. If the account
cannot use `Filter`, the provider logs a warning and carries on unfiltered;
`"ami": { "event_filter": false }` turns the attempt off.

### Yeastar S-Series and P-Series

Yeastar's S-Series and P-Series PBXs are built on Asterisk and expose its
Manager Interface, so the provider works with them like with any other
Asterisk. There is no `manager.conf` to edit; the AMI account is set up in the
web interface instead:

| | S-Series | P-Series |
|---|---|---|
| Where | **Settings › System › Security › AMI** | **Integrations › AMI** |
| Switch | *Enable AMI* | Turn on *AMI* |
| Account | Username and password | Username and password |
| Port | 5038 | 5038, fixed |
| Access | *Permitted IP/Subnet Mask* | *Permitted IP*, up to four entries |

Click **Save and Apply** afterwards. See Yeastar's own guides for the
[S-Series](https://help.yeastar.com/en/s-series/topic/asterisk-manager-interface-ami.html)
and the
[P-Series](https://help.yeastar.com/en/p-series-appliance-edition/administrator-guide/asterisk-manager-interface-overview.html).
Then put the same values into the `ami` block of the configuration.

Things that differ from a plain Asterisk:

- **The permitted IP is the machine running TapiSrv**, not the workstations
  using the TAPI applications. Only that one machine talks to the PBX. With a
  Telephony Server setup, it is the server's address.
- **There are no privilege classes to grant.** Yeastar decides what the AMI
  account may do, so the `read=` / `write=` advice above does not apply. If an
  action the provider needs is refused, the log says so: a refused `Filter`
  only means an unfiltered event stream, a refused `CoreShowChannels` only
  disables the resync. Run `amitsp-ctl discover` and `amitsp-ctl dial` once
  against the PBX to confirm that discovery and Originate work (`dial` rings a
  real phone). If discovery finds no endpoints, list the phones in `lines[]`
  and set `discovery.enabled` to `false`.
- **There is no TLS option on the AMI page**, so leave `ami.tls` off and
  restrict access with the permitted IP list.
- **Extensions dial into Yeastar's own contexts**, such as `DLPN_DialPlan81`
  for extension 81, not into the FreePBX-style `from-internal` that
  `dialplan.context` defaults to. Discovery reads each endpoint's context from
  the PBX, so discovered lines need nothing. A line written by hand in
  `lines[]` needs its `context` set, as in the example configuration, or its
  calls may be rejected with "Extension does not exist". `amitsp-ctl dialplan`
  lists the contexts the PBX actually has. See
  [Which dialplan context outbound calls use](#which-dialplan-context-outbound-calls-use).

## Download

The [latest release](https://github.com/adee42/ami-tsp/releases/latest) has
`ami-tsp-<version>-windows-amd64.zip`. It holds `amitsp.dll`, `amitspui.dll`,
`amitsp-ctl.exe`, the example configuration, this README and the licence. The
three binaries are also attached on their own, and `SHA256SUMS.txt` lists
their checksums:

```powershell
Get-FileHash .\ami-tsp-*-windows-amd64.zip -Algorithm SHA256
```

Extract the zip and follow [Configure](#configure) and [Install](#install),
running `amitsp-ctl.exe` from the extracted folder rather than from `dist\`.
Building it yourself is only needed to change the code.

## Build

```powershell
.\build.ps1
```

Produces `dist\amitsp.dll`, `dist\amitspui.dll` and `dist\amitsp-ctl.exe`. The
script refuses to run against a 32-bit gcc, and prints the DLL's export table
so you can confirm the `TSPI_*` entry points are actually exported.

The build output keeps the `.dll` name; `amitsp-ctl install` is what places it
in `System32` under the conventional `amitsp.tsp` name.

`amitspui.dll` is the install-time UI half, and is plain C rather than cgo on
purpose: TAPI loads it into the process that calls `lineAddProvider`, and a Go
runtime must never be loaded into a client process. See `ui/amitspui.c`.

## Configure

Copy `config\ami-tsp.example.json` to `%ProgramData%\AmiTSP\ami-tsp.json` and
edit it. In practice only the `ami` block has to be right: the line devices
come from the PBX. Override the location with the `AMITSP_CONFIG` environment
variable if you need to — but note the provider runs inside TapiSrv, so it must
be a **machine** environment variable, not a user one.

`number_rules` rewrite what the application dials into what the dialplan
expects; they are applied in order. The defaults strip formatting and turn
`+49…` into `0049…`.

### Which dialplan context outbound calls use

`lineMakeCall` originates to the device and then sends it to
`<number>@<context>`, so that context has to be one the number resolves in. If
it is not, Asterisk rejects the Originate with **"Extension does not exist"**.

Discovery solves this without configuration: `PJSIPShowEndpoint` reports the
context each endpoint dials into, and that is stored per line and used for its
outbound calls. It is the right answer by construction — the number is treated
exactly as if it had been keyed in on that phone. On a Yeastar, for example,
extension 81 originates into `DLPN_DialPlan81`, not into some global context.

`dialplan.context` is only the fallback, for manually configured lines and for
PBXs that report no context. Its default, `from-internal`, is a FreePBX
convention and is wrong on most other systems.

`amitsp-ctl registry` shows the context each line will use, and
`amitsp-ctl dialplan` lists what the PBX actually has:

```powershell
.\dist\amitsp-ctl.exe dialplan                 # every context, with entry counts
.\dist\amitsp-ctl.exe dialplan DLPN_DialPlan81 # one context's extensions and includes
```

A context made only of `include =>` lines still reaches everything they hold —
Asterisk follows includes when it checks whether an extension exists. Both
commands need `read=dialplan` on the manager account.

### Line discovery

With `discovery.enabled` (the default), every PJSIP endpoint on the PBX becomes
a TAPI line device. The endpoint list is read when the AMI link comes up, every
`interval_sec` after that, and immediately when an unfamiliar device registers
or changes state — so a phone plugged in this afternoon shows up this
afternoon, not after the next configuration edit. Each unfamiliar device
triggers that early scan once; a device discovery rejects, such as a trunk, is
not new the next time it changes state, and is left to the periodic scan.

Endpoints are filtered before they become lines:

- `include` — if non-empty, only endpoint names matching one of these regexes
  are considered at all.
- `exclude` — names matching any of these are dropped. The defaults throw out
  the usual carrier-facing names (`trunk`, `gateway`, `gw…`, `provider`).
- `require_aor` — drops endpoints with no AOR, which is what most trunk-side
  endpoints look like.

`amitsp-ctl discover` prints both lists, with a reason per rejected endpoint.
That is the tool for "why is this phone not showing up".

A routine scan only asks the PBX for the details (name, caller ID, dialplan
context) of endpoints it has nothing recorded for, so a steady-state rescan is
a single action. `amitsp-ctl discover --refresh` re-reads them all, which is
how to pick up a phone that was renamed or moved to another dialplan — and the
only way to repair stored details without deleting `lines.json`, which would
renumber every device.

Answer and hold cannot be discovered — they depend on what the *phone* honours,
not on what Asterisk knows — so discovered lines default to `"none"` and their
`LINECALLFEATURE_ANSWER` / `_HOLD` bits stay clear. Set `discovery.defaults` to
turn them on for every discovered line at once, or use `lines[]` per phone.

### The line registry

The PBX is the source of truth for which devices exist, and it is re-read at
every startup and continuously afterwards. `%ProgramData%\AmiTSP\lines.json`
(`AMITSP_REGISTRY` overrides the path) is not a substitute for that — it is
what makes reading the PBX safe.

It exists because TAPI identity cannot come from a live query.
`TSPI_providerEnumDevices` has to report a device count before any connection
exists, device IDs are then handed out by position, and applications store
their per-line preferences against that position and against the permanent line
ID. Rebuild the list from scratch each boot and a PBX that is briefly
unreachable yields no telephony at all, while one endpoint missing mid-reload
shifts every device after it onto the wrong phone.

So the file holds two kinds of field under two different rules:

- **Identity** — channel, slot, permanent ID. Written once, never changed. The
  registry is append-only: a device is never removed or reordered, and one that
  disappears from the PBX keeps its slot and is reported `OUTOFSERVICE` (TAPI
  2.x gives a provider no way to withdraw a device). The file, not `lines[]`,
  is the authority on order, so editing configuration cannot renumber anything.
- **Everything else** — name, caller ID, dialplan context. A cache. The PBX
  wins whenever it speaks; the stored copy only has to answer while it has not.

At startup the provider scans the PBX and enumerates the union of what it finds
and what is on file, so a phone added while the Telephony service was stopped
is in the first device list rather than trickling in later via `LINE_CREATE`. If
the manager port does not accept a connection within a few seconds the scan is
skipped entirely and the stored list is enumerated unchanged — a network outage
must never be mistaken for every phone having been deleted.

#### When a phone is deleted from the PBX

The next scan notices within `interval_sec` and the line goes
`OUTOFSERVICE` — it stays in the device list, because TAPI 2.x gives a provider
no way to withdraw a device and removing one while applications are running
would shift every later device onto the wrong phone. If the endpoint comes back,
the line returns to service on the following scan; no restart is needed.

The entry is **removed from the registry at the next restart of the Telephony
service**, which is the one moment renumbering is safe: nothing has been
reported to TapiSrv yet, so no device ID is invalidated in flight. Devices after
the removed one shift index but **keep their permanent line IDs**, so
applications that key on the permanent ID are unaffected; any that key on the
raw device ID want checking after a phone is decommissioned.

Two things this deliberately does not do:

- **An unregistered phone is never pruned.** `PJSIPShowEndpoints` lists
  configured endpoints whatever their registration state, so a handset that is
  unplugged, powered off or faulty still appears. Only an endpoint actually
  deleted from the PBX disappears from a scan.
- **Nothing is pruned without evidence.** If the PBX cannot be reached at
  startup, or the scan fails, the registry is left exactly as it is. A network
  outage at boot must never be mistaken for every phone having been deleted.

To pin a device so it survives regardless of what the PBX reports, give it a
`lines[]` entry — configured lines are never marked absent and never pruned,
and stay in service whenever the AMI link is up, even if discovery never sees
them (a `SIP/` device, or an endpoint the filters exclude). Deleting the entry
unpins the device: it keeps its slot, and discovery decides from then on
whether it exists.

**Deleting `lines.json` renumbers every device**, and applications will need
their line selection set again. To repair stored details, use
`amitsp-ctl discover --refresh` instead.

`amitsp-ctl registry` prints the stored list; `--probe` runs the same scan
startup does, which is the way to see what the provider would enumerate without
restarting the Telephony service. A `?` in the `PRESENT` column means no scan
has run in that process yet, as opposed to `no`, which means a scan completed
and the device was not in it.

### `lines[]` — manual overrides

`lines[]` is now optional and acts as an override layer. An entry whose
`channel` matches a discovered device replaces that device's name, caller ID
and answer/hold settings; an entry for a channel discovery does not produce is
added as a line of its own. Use it to pin a `permanent_id`, to give a phone a
proper name, or to enable answer/hold on the one model that supports it.

`channel` is the Asterisk device without the per-call suffix (`PJSIP/1001`).
Channel-to-line matching is on the `PJSIP/1001-` prefix, case-insensitively.

Set `discovery.enabled` to `false` for the old behaviour: `lines[]` and nothing
else, and at least one entry required.

### When new lines reach applications

A device found after TapiSrv started is announced with `LINE_CREATE`, which is
the only mechanism TAPI 2.x offers. Applications that re-enumerate on it pick
the line up immediately; plenty of CRM diallers only read the device list once
at startup and will need restarting. Devices already in the registry when
TapiSrv starts are always part of the initial enumeration, so restarting the
Telephony service is the reliable way to make everything visible everywhere.

## Verify before touching TAPI

`amitsp-ctl` talks to AMI using the same code as the provider, so you can
prove the PBX side works with no telephony service involved:

```powershell
.\dist\amitsp-ctl.exe config          # validate, show effective settings
.\dist\amitsp-ctl.exe discover        # scan the PBX, show what becomes a line
.\dist\amitsp-ctl.exe registry        # the device list, in enumeration order
.\dist\amitsp-ctl.exe registry --probe # ...after a live re-scan, as startup does
.\dist\amitsp-ctl.exe dialplan        # the PBX's contexts, when a dial is rejected
.\dist\amitsp-ctl.exe test 120        # watch live call events for 2 minutes
.\dist\amitsp-ctl.exe dial 81 83      # call 83 from the phone on extension 81
.\dist\amitsp-ctl.exe dial "#0" 83    # same, selecting the calling line by index
```

`dial` takes the **calling extension** first, because that is what is written on
the handset. Prefix with `#` to select by line index instead — needed when two
devices answer the same extension, which `dial` refuses to guess between. Either
way a failed lookup lists the known lines, so there is no need to run
`registry` first.

`discover` and `registry` write `lines.json`, so run them as the same user that
TapiSrv does (LocalSystem) or expect the provider to rediscover on its own.

Set `AMITSP_DEBUG=1` for a full AMI protocol trace.

## Install

From an **elevated** prompt (with a [downloaded release](#download), use the
extracted folder in place of `.\dist\`):

```powershell
.\dist\amitsp-ctl.exe install .\dist\amitsp.dll
net stop tapisrv
net start tapisrv
.\dist\amitsp-ctl.exe lines           # should list every discovered endpoint
```

`install` copies the provider to `System32` **as `amitsp.tsp`** and registers
that name with `lineAddProvider`. Service providers are conventionally named
`.tsp` — as every provider Windows ships is — and while the extension has no
technical meaning to TapiSrv, at least one telephony application filters the
lines it offers by the driver file name, so the convention is worth following.

`amitspui.dll` is copied alongside it and keeps its `.dll` name: it is loaded
by the application rather than by TapiSrv and is not itself a service provider.
Both files are required — `TSPI_providerUIIdentify` points TAPI at
`amitspui.dll` next to the provider, and the process calling `lineAddProvider`
loads it from there.

If a build from before the rename is still registered as `amitsp.dll`,
`install` stops and tells you to unregister it first rather than leave TapiSrv
with two copies of the same provider enumerating the same lines. To remove:

```powershell
.\dist\amitsp-ctl.exe list            # find the provider ID
.\dist\amitsp-ctl.exe remove <id>
```

If an application enumerates the provider but offers none of its lines, it is
filtering on a capability bit. `lines -v` prints the whole of `LINEDEVCAPS` and
`LINEADDRESSCAPS` exactly as the application sees them:

```powershell
.\dist\amitsp-ctl.exe lines -v
.\dist\amitsp-ctl.exe lines --api 0x00030000   # does it survive a TAPI 3.0 app?
```

The provider negotiates TSPI 2.2, so an application whose *minimum* API version
is above that gets `LINEERR_INCOMPATIBLEAPIVERSION` per device and silently
lists nothing; `--api` is the direct test for that, and unlike an application,
`lines` reports the failure instead of skipping the device.

If the capabilities all look right and the application still offers nothing,
set `"log": { "level": "debug" }` and restart the Telephony service. The
provider then traces the enumeration path — version negotiation, `lineGetDevCaps`,
`lineGetAddressCaps`, `lineGetID`, `lineGetIcon`, `lineOpen` and the media modes
requested — so the log shows how far the application got before it gave up. Two
things are logged as warnings because they are the usual culprits: a device
class we do not answer, and a request for a vendor extension.

For workstations to use the lines, also run `tcmsetup /c <server>` on the
clients if you are sharing lines through the Telephony Server (TAPI 2.x
remote provider); a purely local install needs nothing further.

## Operating notes

The log is at `%ProgramData%\AmiTSP\ami-tsp.log` (rotated at 8 MB, five
previous files kept as `.1` to `.5`). It is written through a buffer flushed
twice a second, and at once for warnings and errors. Level `debug` records
every AMI packet, and the reason each endpoint was skipped by discovery.

TapiSrv is blocked while `TSPI_providerEnumDevices` runs, so the synchronous
scan performed there is doubly bounded: the manager port must accept a TCP
connection within three seconds, and the scan itself within
`discovery.initial_timeout_sec`. Against a healthy PBX the whole thing takes
about 100 ms. If either bound is hit the provider still loads and enumerates
the stored device list; anything new arrives over `LINE_CREATE` once the AMI
link is up. Every later scan is asynchronous and never blocks a TSPI entry
point.

**A TSP fault takes TapiSrv down with it**, because it runs inside
`svchost.exe`. Two consequences shaped the code:

- The DLL is **pinned** into the process (`GetModuleHandleEx` with
  `GET_MODULE_HANDLE_EX_FLAG_PIN`) during `TSPI_providerInit`. The Go runtime
  cannot survive `FreeLibrary`, and TapiSrv is entitled to unload a provider
  after `TSPI_providerShutdown`.
- Handles given to TAPI are `malloc`ed tokens used only as map keys, never Go
  pointers and never fabricated integers, so they satisfy the cgo pointer
  rules and stay valid under a moving garbage collector.
- Every TSPI entry point and every goroutine recovers from a panic, logs it
  with a stack trace, and carries on. A bug may lose one call; it must not end
  the Telephony service.

The provider asks for `LINETSPIOPTION_NONREENTRANT`, so TapiSrv serialises
calls into it. Every TSPI entry point returns promptly; anything requiring an
AMI round trip is queued to a goroutine and reported through the async
completion callback.

All call messages to TAPI are sent from one goroutine, in the order the PBX
produced them. Events are never dropped: when TapiSrv is slow to take them —
a ring-all queue ringing fifty phones produces several hundred at once — they
wait in an in-order backlog instead. Messages for a call placed with
`lineMakeCall` are held until that request has completed, as TSPI requires,
even when the PBX's events arrive first.

If the AMI link drops, all tracked calls are torn down (`DISCONNECTED` then
`IDLE`) so applications do not keep stale calls on screen, and the lines go
`OUTOFSERVICE` until the client reconnects. Calls still being originated are
failed, so no `lineMakeCall` waits forever.

Whenever the link comes up, and every `ami.resync_sec` (default 60) after that,
the provider compares its calls with the PBX's own channel list
(`CoreShowChannels`). Calls in progress when the link came up are picked up;
calls whose hangup never arrived are cleared. It is a repair for what the event
stream failed to convey, not the main mechanism.

Each line reports `tapi.max_calls_per_line` (default 4) as its call limit, and
calls beyond it are not offered to applications (the log says so). Raise it for
a device that many callers share, such as a reception or queue line.

## Layout

```
tsp/                     the provider DLL (package main, buildmode=c-shared)
  shim.h, shim.c         TSPI types and the callback trampolines into TAPI
  exports_provider.go    TSPI_provider* — lifecycle and device enumeration
  exports_line.go        TSPI_line* — device capabilities and status
  exports_call.go        TSPI_line* — call control
  structs.go             filling TAPI's variable-length structures
  bridge.go              PBX events -> LINE_* messages
  state.go               provider state and handle tables
internal/ami/            reconnecting AMI client, action/response correlation
internal/pbx/            AMI event stream -> call model (the actual proxy logic)
  discover.go            PJSIP endpoint discovery and the rescan loop
internal/lines/          the append-only, persisted line device registry
internal/config/         configuration
internal/logx/           file logger
cmd/amitsp-ctl/          install, remove, list, and AMI diagnostics
ui/amitspui.c            TUISPI_* install-time entry points, plain C
```

The `internal/pbx` package holds the interesting part: the state machine that
decides, from `Newchannel` / `DialBegin` / `Newstate`, whether a channel is an
inbound or outbound call and who the other party is. It is deliberately free
of TAPI types so it can be exercised from `amitsp-ctl` without a telephony
service.
