package ami

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/adee42/ami-tsp/internal/config"
)

// fakeManager is just enough of Asterisk's manager to log a client in. After
// the login, every packet the client sends is handed to onPacket, which writes
// whatever answer it likes; returning false drops the connection.
type fakeManager struct {
	ln       net.Listener
	onPacket func(w net.Conn, p *Message) bool
}

func newFakeManager(t *testing.T, onPacket func(w net.Conn, p *Message) bool) (*fakeManager, config.AMI) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeManager{ln: ln, onPacket: onPacket}
	go f.serve()
	cfg := config.AMI{
		Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		ConnectTimeoutSec: 2, ActionTimeoutSec: 5, KeepaliveSec: 300,
		// Long enough that a dropped test connection is not retried mid-test.
		ReconnectMinSec: 60, ReconnectMaxSec: 60,
	}
	return f, cfg
}

func (f *fakeManager) serve() {
	c, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	r := bufio.NewReader(c)
	_, _ = c.Write([]byte("Asterisk Call Manager/5.0.0\r\n"))
	login, err := readPacket(r)
	if err != nil {
		return
	}
	_, _ = c.Write(NewMessage("Response", "Success", "ActionID", login.ActionID(), "Message", "Authentication accepted").Bytes())
	for {
		p, err := readPacket(r)
		if err != nil {
			return
		}
		if !f.onPacket(c, p) {
			return
		}
	}
}

// startClient connects and waits for the login to complete.
func startClient(t *testing.T, cfg config.AMI, filter string) *Client {
	t.Helper()
	up := make(chan struct{}, 1)
	cl := New(cfg, nil, func(b bool) {
		if b {
			up <- struct{}{}
		}
	})
	cl.SetEventFilter(filter)
	cl.Start()
	t.Cleanup(cl.Stop)
	select {
	case <-up:
	case <-time.After(5 * time.Second):
		t.Fatal("client never logged in")
	}
	return cl
}

// TestDisconnectDuringAction is the crash this test exists for: a connection
// that drops while an action waits for its response used to hand Action a nil
// response, and logging it dereferenced nil. Inside TapiSrv that panic ended
// svchost, and with it telephony for every application on the machine.
func TestDisconnectDuringAction(t *testing.T) {
	_, cfg := newFakeManager(t, func(net.Conn, *Message) bool { return false })
	cl := startClient(t, cfg, "")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := cl.Action(ctx, NewMessage("Action", "Hangup", "Channel", "PJSIP/1001-00000001"))
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Action across a dropped connection returned %v, want ErrNotConnected", err)
	}
}

// TestEventFilterIsInstalled checks that the whitelist goes out with the
// session, before anything else is sent.
func TestEventFilterIsInstalled(t *testing.T) {
	got := make(chan *Message, 4)
	_, cfg := newFakeManager(t, func(w net.Conn, p *Message) bool {
		got <- p
		_, _ = w.Write(NewMessage("Response", "Success", "ActionID", p.ActionID()).Bytes())
		return true
	})
	startClient(t, cfg, "Event: (Newchannel|Hangup)")

	select {
	case p := <-got:
		if !strings.EqualFold(p.Get("Action"), "Filter") || p.Get("Operation") != "Add" ||
			p.Get("Filter") != "Event: (Newchannel|Hangup)" {
			t.Errorf("first action after login = %s, want the event filter", p.Redacted())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event filter was sent")
	}
}

// TestRefusedFilterIsNotFatal: an account without write=system cannot filter,
// and must still get a working, unfiltered session.
func TestRefusedFilterIsNotFatal(t *testing.T) {
	_, cfg := newFakeManager(t, func(w net.Conn, p *Message) bool {
		resp := "Success"
		if strings.EqualFold(p.Get("Action"), "Filter") {
			resp = "Error"
		}
		_, _ = w.Write(NewMessage("Response", resp, "ActionID", p.ActionID(), "Message", "Permission denied").Bytes())
		return true
	})
	cl := startClient(t, cfg, "Event: Hangup")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cl.Action(ctx, NewMessage("Action", "Ping")); err != nil {
		t.Fatalf("session unusable after a refused filter: %v", err)
	}
}
