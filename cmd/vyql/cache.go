package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/internal/extract/parsecache"
)

// cmdCache implements `vyql cache`, the lifecycle the scan cache otherwise has none of.
//
// `clear` in particular is not a convenience. PrefetchStubs trusts size+mtime like any build
// cache, so a content change that preserves both is missed; its own doc names `vyql cache clear`
// as the recovery path, and until now that command did not exist. A user hitting the one
// acknowledged unsoundness had to know to delete an undocumented directory by hand.
func cmdCache(args []string) error {
	// The subcommand is pulled out before flag parsing, so `cache clear -cache DIR` works.
	// flag.Parse stops at the first non-flag argument, so leaving `clear` in front would make
	// every flag after it silently ignored -- and a -cache pointing somewhere else being ignored
	// means clearing the wrong directory while reporting success.
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("cache", flag.ExitOnError)
	dir := fs.String("cache", "auto", "cache location: auto | <dir>")
	_ = fs.Parse(args)
	if sub == "" {
		if rest := fs.Args(); len(rest) > 0 {
			sub = rest[0]
		}
	}

	path := resolveCacheDir(*dir)
	switch sub {
	case "path":
		fmt.Println(path)
		return nil
	case "clear":
		return clearCache(path)
	default:
		fmt.Fprintln(os.Stderr, "usage: vyql cache <clear|path> [-cache auto|<dir>]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  clear   drop every cached parse, delta, label and scan result")
		fmt.Fprintln(os.Stderr, "  path    print the cache directory this build would use")
		return fmt.Errorf("cache: expected a subcommand")
	}
}

// resolveCacheDir mirrors applyScanCache's resolution so `cache path` and `cache clear` act on the
// directory a scan would actually use, rather than a second guess at it.
func resolveCacheDir(v string) string {
	if v == "" || v == "auto" {
		base, err := os.UserCacheDir()
		if err != nil || base == "" {
			base = filepath.Join(os.TempDir(), "vyql-cache")
		}
		return filepath.Join(base, "vyql", "scan-cache")
	}
	return v
}

func clearCache(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("cache %s: nothing to clear\n", path)
		return nil
	}
	cache, err := parsecache.Open(path)
	if err != nil {
		// An unopenable cache is exactly the case a user most needs cleared -- a half-written or
		// format-incompatible directory. Removing it is the honest fallback, and safe: every
		// entry is reproducible from source.
		if rmErr := os.RemoveAll(path); rmErr != nil {
			return fmt.Errorf("cache %s: cannot open (%v) and cannot remove: %w", path, err, rmErr)
		}
		fmt.Printf("cache %s: could not be opened, so removed instead\n", path)
		return nil
	}
	defer func() { _ = cache.Close() }()
	if err := cache.Clear(); err != nil {
		return fmt.Errorf("cache %s: %w", path, err)
	}
	fmt.Printf("cache %s: cleared\n", path)
	return nil
}
