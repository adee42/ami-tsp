package ami

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adee42/ami-tsp/internal/config"
	"github.com/adee42/ami-tsp/internal/logx"
)

// ErrNotConnected is returned when an action is attempted while the manager
// connection is down. Callers map this to a TAPI error rather than blocking,
// because TSPI entry points must never stall TapiSrv.
var ErrNotConnected = errors.New("ami: not connected")

// Client is a reconnecting AMI connection.
//
// One goroutine owns the socket read side; writes are serialised by a mutex.
// Actions are correlated to responses by ActionID.
type Client struct {
	cfg     config.AMI
	onEvent func(*Message)
	onState func(bool)

	writeMu sync.Mutex
	conn    net.Conn

	// filter, when set, is installed with the Filter action right after
	// login, so that Asterisk only sends the events that match it.
	filter string

	mu        sync.Mutex
	pending   map[string]chan *Message
	listeners map[string]*listener
	connected bool

	seq     uint64
	healthy atomic.Bool // last session reached the logged-in state
	stopCh  chan struct{}
	stopOn  sync.Once
	wg      sync.WaitGroup
}

// New creates a client. onEvent is called for every AMI event from the
// reader goroutine, so it must not block for long. onState is called on
// connect (true) and disconnect (false); either callback may be nil.
func New(cfg config.AMI, onEvent func(*Message), onState func(bool)) *Client {
	return &Client{
		cfg:       cfg,
		onEvent:   onEvent,
		onState:   onState,
		pending:   make(map[string]chan *Message),
		listeners: make(map[string]*listener),
		stopCh:    make(chan struct{}),
	}
}

// listener collects the event stream of one list action.
type listener struct {
	ch chan *Message

	// overflow is closed when the reader had to drop one of this list's
	// events. The list is then incomplete and is reported as failed rather
	// than returned short.
	overflow     chan struct{}
	overflowOnce sync.Once
}

// listBuffer is how many list events may queue for a collector. Collectors do
// nothing but append, so this only fills if one is starved of CPU.
const listBuffer = 4096

// SetEventFilter installs an event whitelist on every session: a POSIX
// extended regular expression that Asterisk matches against the text of each
// event, sending only those that match. It must be called before Start.
//
// Responses, and the events that answer list actions, are not subject to it.
// If the manager account may not use the Filter action, the session carries
// on unfiltered and the log says so.
func (c *Client) SetEventFilter(re string) { c.filter = re }

// Start launches the connect/reconnect loop and returns immediately.
func (c *Client) Start() {
	c.wg.Add(1)
	go c.run()
}

// Stop closes the connection and waits for the loop to finish.
func (c *Client) Stop() {
	c.stopOn.Do(func() { close(c.stopCh) })
	c.closeConn()
	c.wg.Wait()
}

// Reachable reports whether the manager port accepts a TCP connection.
//
// It is a precondition for work that must not block. Waiting for a login that
// will never arrive costs the whole action window; a dial that a firewall
// blackholes can be abandoned after a second or two, and a refused port fails
// in milliseconds. Nothing is sent, so an unreachable PBX costs one SYN.
func Reachable(cfg config.AMI, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	if err != nil {
		logx.Debugf("ami: %s:%d not reachable: %v", cfg.Host, cfg.Port, err)
		return false
	}
	_ = conn.Close()
	return true
}

// Connected reports whether a logged-in connection currently exists.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *Client) run() {
	defer c.wg.Done()
	defer logx.Recover("ami: connection loop")

	backoff := time.Duration(c.cfg.ReconnectMinSec) * time.Second
	maxBackoff := time.Duration(c.cfg.ReconnectMaxSec) * time.Second

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		err := c.session()
		if err != nil {
			logx.Warnf("ami: session ended: %v", err)
		}

		select {
		case <-c.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		// A session that got as far as logging in resets the backoff, so a
		// PBX restart does not push us out to the maximum retry interval.
		if c.healthy.Swap(false) {
			backoff = time.Duration(c.cfg.ReconnectMinSec) * time.Second
		}
	}
}

// session runs one full connect-login-read cycle and returns when it ends.
func (c *Client) session() error {
	addr := net.JoinHostPort(c.cfg.Host, fmt.Sprint(c.cfg.Port))
	dialer := &net.Dialer{Timeout: time.Duration(c.cfg.ConnectTimeoutSec) * time.Second}

	var conn net.Conn
	var err error
	if c.cfg.TLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         c.cfg.Host,
			InsecureSkipVerify: c.cfg.InsecureSkipVerify,
		})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// Publish the connection before the first read rather than after login.
	// closeConn is how Stop unblocks this goroutine, and until c.conn is set
	// it has nothing to close: a Stop arriving during the banner or login
	// exchange would otherwise wait out the whole connect timeout. That wait
	// happens inside TSPI_providerShutdown, where TapiSrv is holding every
	// TAPI application on the machine behind it.
	c.writeMu.Lock()
	c.conn = conn
	c.writeMu.Unlock()

	r := bufio.NewReaderSize(conn, 16<<10)

	// Greeting: "Asterisk Call Manager/x.y.z"
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(c.cfg.ConnectTimeoutSec) * time.Second))
	banner, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read banner: %w", err)
	}
	logx.Infof("ami: connected to %s (%s)", addr, strings.TrimSpace(banner))

	if err := c.login(conn, r); err != nil {
		return err
	}
	if c.filter != "" {
		c.installFilter(conn, r)
	}
	_ = conn.SetReadDeadline(time.Time{})

	c.setConnected(true)
	c.healthy.Store(true)
	defer c.setConnected(false)

	stopKeepalive := make(chan struct{})
	defer close(stopKeepalive)
	go c.keepalive(stopKeepalive)

	// Read until the socket dies or Stop is called.
	for {
		msg, err := readPacket(r)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		c.dispatch(msg)
	}
}

// login performs the Login action inline, before the general reader starts,
// so that a bad password produces a clear error instead of a silent retry.
func (c *Client) login(conn net.Conn, r *bufio.Reader) error {
	req := NewMessage(
		"Action", "Login",
		"ActionID", c.nextActionID(),
		"Username", c.cfg.Username,
		"Secret", c.cfg.Secret,
		"Events", "on",
	)

	if _, err := conn.Write(req.Bytes()); err != nil {
		return fmt.Errorf("send login: %w", err)
	}
	// Some Asterisk builds emit an event (FullyBooted, for one) before the
	// login response, so skip forward to the first packet that answers.
	var resp *Message
	for i := 0; i < 16; i++ {
		p, err := readPacket(r)
		if err != nil {
			return fmt.Errorf("read login response: %w", err)
		}
		if p.Response() != "" {
			resp = p
			break
		}
	}
	if resp == nil {
		return fmt.Errorf("no login response from manager")
	}
	if !resp.Success() {
		return fmt.Errorf("login rejected: %s", resp.Get("Message"))
	}
	logx.Infof("ami: logged in as %q", c.cfg.Username)
	return nil
}

// installFilter sends the event whitelist inline, like login, so that it is
// in place before the reader starts and the first burst of events is already
// filtered. It is one Filter action with one expression: a whitelist that was
// only partly installed would silently hide events the monitor needs.
//
// Failure is not fatal. The unfiltered stream works, it is just much larger.
func (c *Client) installFilter(conn net.Conn, r *bufio.Reader) {
	id := c.nextActionID()
	req := NewMessage("Action", "Filter", "ActionID", id, "Operation", "Add", "Filter", c.filter)
	if _, err := conn.Write(req.Bytes()); err != nil {
		logx.Warnf("ami: cannot send event filter: %v", err)
		return
	}
	// Events that arrive before the answer are dropped. Nothing is tracked
	// yet, and the resync that follows every login catches up on calls.
	for i := 0; i < 64; i++ {
		p, err := readPacket(r)
		if err != nil {
			logx.Warnf("ami: no answer to event filter: %v", err)
			return
		}
		if p.Response() == "" || p.ActionID() != id {
			continue
		}
		if !p.Success() {
			logx.Warnf("ami: event filter refused (%s); receiving every event. "+
				"Grant write=system to the manager account, or set ami.event_filter to false",
				p.Get("Message"))
			return
		}
		logx.Debugf("ami: event filter installed")
		return
	}
	logx.Warnf("ami: no answer to event filter; receiving every event")
}

func (c *Client) keepalive(stop <-chan struct{}) {
	defer logx.Recover("ami: keepalive")

	iv := time.Duration(c.cfg.KeepaliveSec) * time.Second
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-c.stopCh:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), iv)
			_, err := c.Action(ctx, NewMessage("Action", "Ping"))
			cancel()
			if err != nil {
				logx.Warnf("ami: keepalive failed (%v), dropping connection", err)
				c.closeConn()
				return
			}
		}
	}
}

// dispatch routes a packet to a waiting action, to a list collector, or to the
// event handler.
func (c *Client) dispatch(m *Message) {
	id := m.ActionID()

	if id != "" && m.Response() != "" {
		c.mu.Lock()
		ch, ok := c.pending[id]
		if ok {
			delete(c.pending, id)
		}
		c.mu.Unlock()
		if ok {
			select {
			case ch <- m:
			default:
			}
			return
		}
	}

	if m.Event() == "" {
		return
	}

	// List actions answer with an ordinary response (handled above) followed
	// by a stream of events carrying the same ActionID. Those belong to the
	// caller of ActionList, not to the general event handler.
	if id != "" {
		c.mu.Lock()
		l, ok := c.listeners[id]
		c.mu.Unlock()
		if ok {
			select {
			case l.ch <- m:
			default:
				// The collector is not keeping up. Waiting would stall the
				// reader, which freezes call events for every line, so the
				// list is abandoned instead and its caller told so.
				l.overflowOnce.Do(func() {
					logx.Warnf("ami: list collector for %s is not draining, abandoning the list", id)
					close(l.overflow)
				})
			}
			return
		}
	}

	if c.onEvent != nil {
		c.deliver(m)
	}
}

// deliver hands one event to the handler. A panic in the handler loses that
// event, not the connection and certainly not the process.
func (c *Client) deliver(m *Message) {
	defer logx.Recover("ami: event handler for " + m.Event())
	c.onEvent(m)
}

// ActionList sends an action that answers with a stream of events and collects
// them until completeEvent arrives.
//
// Asterisk answers these with "Response: Success" first, then one event per
// item, then a terminating event; all of them carry the request's ActionID.
// The terminating event is returned as part of the slice so that callers can
// read its ListItems count if they want to.
func (c *Client) ActionList(ctx context.Context, m *Message, completeEvent string) ([]*Message, error) {
	id := m.ActionID()
	if id == "" {
		id = c.nextActionID()
		m.Set("ActionID", id)
	}

	// Register before sending: the first event can arrive before Action has
	// even returned its response.
	l := &listener{ch: make(chan *Message, listBuffer), overflow: make(chan struct{})}
	ch := l.ch
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, ErrNotConnected
	}
	c.listeners[id] = l
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.listeners, id)
		c.mu.Unlock()
	}()

	if _, err := c.Action(ctx, m); err != nil {
		return nil, err
	}

	var out []*Message
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return out, ErrNotConnected
			}
			out = append(out, msg)
			if strings.EqualFold(msg.Event(), completeEvent) {
				return out, nil
			}
			if len(out) > 10000 {
				return out, fmt.Errorf("ami: list %q exceeded 10000 items", m.Get("Action"))
			}
		case <-l.overflow:
			return out, fmt.Errorf("ami: list %q dropped events, result incomplete", m.Get("Action"))
		case <-ctx.Done():
			return out, ctx.Err()
		case <-c.stopCh:
			return out, ErrNotConnected
		}
	}
}

// Action sends an action and waits for its response.
func (c *Client) Action(ctx context.Context, m *Message) (*Message, error) {
	id := m.ActionID()
	if id == "" {
		id = c.nextActionID()
		m.Set("ActionID", id)
	}

	ch := make(chan *Message, 1)
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, ErrNotConnected
	}
	c.pending[id] = ch
	c.mu.Unlock()

	cleanup := func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}

	if err := c.write(m); err != nil {
		cleanup()
		return nil, err
	}
	// Arguments are evaluated whether or not the line is logged, and
	// rendering a packet is not free on a busy link.
	debug := logx.Enabled(logx.LevelDebug)
	if debug {
		logx.Debugf("ami: -> %s", m.Redacted())
	}

	select {
	case resp := <-ch:
		if resp == nil {
			// setConnected(false) closes every pending channel: the
			// connection dropped before the answer arrived.
			return nil, ErrNotConnected
		}
		if debug {
			logx.Debugf("ami: <- %s", resp.Redacted())
		}
		if !resp.Success() {
			return resp, fmt.Errorf("ami: action %q failed: %s", m.Get("Action"), resp.Get("Message"))
		}
		return resp, nil
	case <-ctx.Done():
		cleanup()
		return nil, ctx.Err()
	case <-c.stopCh:
		cleanup()
		return nil, ErrNotConnected
	}
}

func (c *Client) write(m *Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.conn == nil {
		return ErrNotConnected
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Duration(c.cfg.ActionTimeoutSec) * time.Second))
	_, err := c.conn.Write(m.Bytes())
	return err
}

func (c *Client) closeConn() {
	c.writeMu.Lock()
	conn := c.conn
	c.conn = nil
	c.writeMu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (c *Client) setConnected(v bool) {
	c.mu.Lock()
	changed := c.connected != v
	c.connected = v
	if !v {
		// Release everyone waiting on a response or on a list stream.
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		for id, l := range c.listeners {
			close(l.ch)
			delete(c.listeners, id)
		}
	}
	c.mu.Unlock()
	if changed && c.onState != nil {
		c.onState(v)
	}
}

func (c *Client) nextActionID() string {
	n := atomic.AddUint64(&c.seq, 1)
	return fmt.Sprintf("amitsp-%d-%d", time.Now().UnixNano()/1e6, n)
}

// readPacket reads lines until the blank line that terminates an AMI packet.
func readPacket(r *bufio.Reader) (*Message, error) {
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if len(lines) == 0 {
				continue // tolerate stray blank lines
			}
			return parsePacket(lines), nil
		}
		lines = append(lines, line)
		if len(lines) > 512 {
			return nil, errors.New("ami: packet too large")
		}
	}
}
