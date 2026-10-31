// Package logx is a tiny dependency-free file logger.
//
// The TSP runs inside TapiSrv (svchost.exe) where there is no console and no
// reliable way to attach a debugger, so a log file is the only diagnostic
// channel. Everything here must be safe to call before Configure and from any
// goroutine.
//
// Writes are buffered and flushed by a background ticker, because the busiest
// caller is the AMI reader goroutine and a file write per line would put disk
// latency on the path every call event takes. Warnings and errors are flushed
// at once, so the lines that explain a failure are on disk before it matters.
package logx

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

const (
	maxSize = 8 << 20 // rotate at 8 MiB
	keep    = 5       // previous files kept: path.1 (newest) .. path.5

	flushInterval = 500 * time.Millisecond
	bufferSize    = 64 << 10
)

var (
	mu   sync.Mutex
	out  *os.File
	buf  *bufio.Writer
	path string
	size int64

	// level is read on every log call, including the ones that end up
	// filtered out, so it is kept outside the mutex.
	level atomic.Int32

	flusherOnce sync.Once
)

func init() { level.Store(int32(LevelInfo)) }

// ParseLevel maps a config string to a Level, defaulting to info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return LevelError
	case "warn", "warning":
		return LevelWarn
	case "debug", "trace":
		return LevelDebug
	default:
		return LevelInfo
	}
}

// Configure opens (or reopens) the log destination. An empty path disables
// logging; "-" writes to stderr, which is what the command line tool wants.
// The process keeps running either way, because a broken log destination
// must never stop the telephony service provider from loading.
func Configure(file string, lvl Level) {
	mu.Lock()
	defer mu.Unlock()

	level.Store(int32(lvl))
	closeLocked()
	path = file
	switch path {
	case "":
		return
	case "-":
		out = os.Stderr
		size = 0
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	out = f
	buf = bufio.NewWriterSize(f, bufferSize)
	size = 0
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	flusherOnce.Do(func() { go flusher() })
}

// Close flushes and closes the log file.
func Close() {
	mu.Lock()
	defer mu.Unlock()
	closeLocked()
}

// Flush writes out anything buffered.
func Flush() {
	mu.Lock()
	defer mu.Unlock()
	if buf != nil {
		_ = buf.Flush()
	}
}

func closeLocked() {
	if buf != nil {
		_ = buf.Flush()
		buf = nil
	}
	if out != nil && out != os.Stderr {
		out.Close()
	}
	out = nil
}

// flusher bounds how long a line can sit in the buffer. It lives as long as
// the process: the DLL is pinned, so there is no unload for it to outlive.
func flusher() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for range t.C {
		Flush()
	}
}

func Enabled(l Level) bool { return l <= Level(level.Load()) }

func Errorf(format string, a ...any) { emit(LevelError, "ERROR", format, a...) }
func Warnf(format string, a ...any)  { emit(LevelWarn, "WARN ", format, a...) }
func Infof(format string, a ...any)  { emit(LevelInfo, "INFO ", format, a...) }
func Debugf(format string, a ...any) { emit(LevelDebug, "DEBUG", format, a...) }

// Recover logs a panic instead of letting it end the process. It must be
// deferred directly:
//
//	defer logx.Recover("what this goroutine does")
//
// The provider runs inside TapiSrv, where an unrecovered panic on any
// goroutine takes telephony down for every application on the machine. A bug
// that loses one call is far better than that.
func Recover(what string) {
	if r := recover(); r != nil {
		Errorf("panic in %s: %v\n%s", what, r, debug.Stack())
	}
}

func emit(l Level, tag, format string, a ...any) {
	if !Enabled(l) {
		return
	}
	line := fmt.Sprintf("%s %s %s\n", time.Now().Format("2006-01-02 15:04:05.000"), tag, fmt.Sprintf(format, a...))

	mu.Lock()
	defer mu.Unlock()
	if out == nil {
		return
	}
	if out == os.Stderr {
		_, _ = out.WriteString(line)
		return
	}
	n, err := buf.WriteString(line)
	if err != nil {
		return
	}
	if l <= LevelWarn {
		_ = buf.Flush()
	}
	size += int64(n)
	if size >= maxSize {
		rotateLocked()
	}
}

// rotateLocked is called with mu held.
func rotateLocked() {
	_ = buf.Flush()
	out.Close()
	out, buf = nil, nil
	_ = os.Remove(fmt.Sprintf("%s.%d", path, keep))
	for i := keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	_ = os.Rename(path, path+".1")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	out = f
	buf = bufio.NewWriterSize(f, bufferSize)
	size = 0
}
