package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Cleanups that must run before the process goes away, whether it returns
// normally or is interrupted.
//
// A deferred cleanup covers the first case only. `scan -max-ram` puts the graph
// in a badger store under a temporary directory, and interrupting that scan left
// the whole on-disk graph behind with no command to remove it -- on the scans
// large enough to want a RAM ceiling, which are the ones most likely to be
// interrupted.

var cleanups struct {
	mu  sync.Mutex
	fns []func()
}

// onExit registers a cleanup and returns it wrapped so it runs exactly once. The
// caller still defers the returned function: the deferred call is what runs on
// the normal path, and the registry is what runs on a signal. Whichever happens
// first, the other becomes a no-op.
func onExit(f func()) func() {
	var once sync.Once
	wrapped := func() { once.Do(f) }
	cleanups.mu.Lock()
	cleanups.fns = append(cleanups.fns, wrapped)
	cleanups.mu.Unlock()
	return wrapped
}

// runCleanups runs every registered cleanup, most recent first, so a cleanup
// unwinds in the order a deferred one would.
func runCleanups() {
	cleanups.mu.Lock()
	fns := make([]func(), len(cleanups.fns))
	copy(fns, cleanups.fns)
	cleanups.mu.Unlock()
	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

// watchForInterrupt runs the cleanups when the process is asked to stop, then
// exits with the conventional status for that signal: 128 plus the signal
// number, which is what a shell reports and what a CI runner expects.
//
// SIGKILL cannot be caught, so a hard kill still leaves a temporary store behind.
// `vyql cache clear` does not remove it either -- it is not the cache. The path is
// printed on interrupt so it can be removed by hand if a later kill orphans one.
func watchForInterrupt() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-ch
		fmt.Fprintf(os.Stderr, "vyql: %s; cleaning up\n", sig)
		runCleanups()
		code := 1
		if s, ok := sig.(syscall.Signal); ok {
			code = 128 + int(s)
		}
		os.Exit(code)
	}()
}
