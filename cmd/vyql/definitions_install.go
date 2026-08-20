package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vyprai/vyql/internal/datadir"
)

// ensureDataDirectory installs the free definitions bundle when the user agrees.
// A non-interactive invocation keeps the existing error so CI and scripts stay predictable.
func ensureDataDirectory() error {
	if _, ok := datadir.Lookup(); ok {
		return nil
	}
	if !stdinIsInteractive() {
		return errNoDataDirectory
	}
	fmt.Fprintln(os.Stderr, "vyql: no data directory found.")
	fmt.Fprint(os.Stderr, "Download the free definitions from dl.vyprsec.ai? [y/N] ")
	if !readYesNo(os.Stdin) {
		return errNoDataDirectory
	}
	dest, err := datadir.DefaultInstallDir()
	if err != nil {
		return fmt.Errorf("default install directory: %w", err)
	}
	fmt.Fprintf(os.Stderr, "vyql: downloading definitions to %s …\n", dest)
	if err := datadir.InstallFree(dest); err != nil {
		return fmt.Errorf("download definitions: %w", err)
	}
	if err := os.Setenv("VYQL_HOME", dest); err != nil {
		return err
	}
	datadir.Reset()
	fmt.Fprintf(os.Stderr, "vyql: installed definitions %s\n", dest)
	return nil
}

func stdinIsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func readYesNo(r io.Reader) bool {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
