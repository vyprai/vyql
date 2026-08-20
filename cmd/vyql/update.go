package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/vyprai/vyql/internal/datadir"
)

// cmdUpdate checks dl.vyprsec.ai for a newer free definitions bundle and installs it.
func cmdUpdate(args []string) error {
	fs := newFlagSet("update")
	yes := fs.Bool("yes", false, "download without asking")
	checkOnly := fs.Bool("check", false, "report whether an update is available and exit")
	addDataFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	remote, err := datadir.FetchManifest(false)
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}

	localRoot, hasLocal := datadir.Lookup()
	localVer := ""
	if hasLocal {
		localVer, err = datadir.ReadVersion(localRoot)
		if err != nil {
			return fmt.Errorf("read installed version: %w", err)
		}
	}

	newer := datadir.NeedsUpdate(localVer, remote.Version)

	if *checkOnly {
		if !newer {
			fmt.Printf("definitions are up to date (%s)\n", localVer)
			return nil
		}
		if hasLocal {
			fmt.Printf("update available: %s -> %s\n", localVer, remote.Version)
		} else {
			fmt.Printf("no definitions installed; latest is %s\n", remote.Version)
		}
		return checkFailedf("update available")
	}

	if !newer {
		fmt.Printf("definitions are up to date (%s)\n", localVer)
		return nil
	}

	if !*yes {
		if !stdinIsInteractive() {
			return usageWith("update needs a terminal or -yes",
				"run `vyql update -yes` to download without prompting")
		}
		if hasLocal {
			fmt.Fprintf(os.Stderr, "Download definitions %s -> %s from dl.vyprsec.ai? [y/N] ", localVer, remote.Version)
		} else {
			fmt.Fprintf(os.Stderr, "Download definitions %s from dl.vyprsec.ai? [y/N] ", remote.Version)
		}
		if !readYesNo(os.Stdin) {
			return errors.New("update cancelled")
		}
	}

	dest, err := installDestination(localRoot, hasLocal)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "vyql: downloading definitions to %s …\n", dest)
	if err := datadir.InstallManifest(remote, dest); err != nil {
		return fmt.Errorf("download definitions: %w", err)
	}
	datadir.Set(dest)
	fmt.Printf("installed definitions %s\n", remote.Version)
	return nil
}

func installDestination(localRoot string, hasLocal bool) (string, error) {
	if hasLocal {
		return localRoot, nil
	}
	if env := strings.TrimSpace(os.Getenv("VYQL_HOME")); env != "" {
		return env, nil
	}
	return datadir.DefaultInstallDir()
}
