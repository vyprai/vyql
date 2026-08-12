package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// The directory is removed rather than emptied. Dropping the keys leaves
	// badger's own files -- a preallocated 1 MB DISCARD, the manifest, the key
	// registry -- so a cache reported as cleared still occupies megabytes, which
	// is not what someone reclaiming disk asked for.
	//
	// Removing it also covers the case that most needs clearing: a half-written or
	// format-incompatible directory that cannot be opened at all. It is safe
	// either way, because every entry is reproducible from source and the next
	// scan recreates the directory.
	freed := dirBytes(path)
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("cache %s: %w", path, err)
	}
	fmt.Printf("cache %s: cleared, %s freed\n", path, humanBytes(freed))
	return nil
}

// dirBytes totals the files under path. A cache that cannot be walked reports
// zero rather than failing: the number is for the operator, and refusing to clear
// because the size could not be measured would be the wrong trade.
func dirBytes(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
