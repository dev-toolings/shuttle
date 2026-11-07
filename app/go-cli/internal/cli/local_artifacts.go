package cli

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

func safeArtifactName(value string) string {
	value = strings.ToLower(value)
	var out strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out.WriteRune(r)
		} else {
			out.WriteByte('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

func allocateLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// interruptCleanup runs registered cleanup actions on SIGINT/SIGTERM.
type interruptCleanup struct {
	mu      sync.Mutex
	actions []func() error
	signals chan os.Signal
	done    chan struct{}
	stopped sync.Once
}

func newInterruptCleanup() *interruptCleanup {
	c := &interruptCleanup{
		signals: make(chan os.Signal, 1),
		done:    make(chan struct{}),
	}
	signal.Notify(c.signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-c.signals:
			c.Run()
			// os.Exit is intentional: after an operator interrupt, continuing a
			// half-applied deployment is less safe than stopping here.
			os.Exit(130)
		case <-c.done:
		}
	}()
	return c
}

// Add is nil-safe so callers can wire it on a dry run without branching.
func (c *interruptCleanup) Add(action func() error) {
	if c == nil || action == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actions = append(c.actions, action)
}

func (c *interruptCleanup) Run() {
	if c == nil {
		return
	}
	c.mu.Lock()
	actions := make([]func() error, len(c.actions))
	copy(actions, c.actions)
	c.mu.Unlock()
	for i := len(actions) - 1; i >= 0; i-- {
		if err := actions[i](); err != nil {
			fmt.Fprintf(os.Stderr, "shuttle cleanup failed: %v\n", err)
		}
	}
}

func (c *interruptCleanup) Stop() {
	if c == nil {
		return
	}
	c.stopped.Do(func() {
		signal.Stop(c.signals)
		close(c.done)
	})
}
