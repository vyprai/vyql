package main

import (
	"fmt"
	"os"

	"github.com/vyprai/vyql/extract/parsecache"
)

// cmdCache manages the on-disk parse/scan cache (the $VYQL_CACHE directory).
//
//	vyql cache clear   — drop all cached parse results and scan results
func cmdCache(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "clear":
		dir := os.Getenv("VYQL_CACHE")
		if dir == "" {
			return fmt.Errorf("VYQL_CACHE is not set — caching is disabled, nothing to clear")
		}
		c := parsecache.Shared()
		if c == nil {
			return fmt.Errorf("could not open cache at %s", dir)
		}
		if err := c.Clear(); err != nil {
			return fmt.Errorf("clear cache: %w", err)
		}
		_ = c.Close()
		fmt.Printf("cleared cache at %s\n", dir)
		return nil
	default:
		return fmt.Errorf("usage: vyql cache clear   (cache dir = $VYQL_CACHE)")
	}
}
