package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vyprai/vyql/agenticprep"
)

type prepCLIConfig struct {
	OutDir       string
	Provider     string
	Project      string
	Location     string
	Model        string
	Creds        string
	ContextCache bool
	Debug        bool
}

func cmdPrep(args []string) error {
	fs := flag.NewFlagSet("prep", flag.ExitOnError)
	outDir := fs.String("out", os.Getenv("VYQL_AGENTIC_PREP_OUT"), "output directory for manifest and adapter overlay")
	provider := fs.String("provider", envDefault("VYQL_AGENTIC_PREP_PROVIDER", "off"), "provider: off | vertex")
	project := fs.String("vertex-project", os.Getenv("VYQL_VERTEX_PROJECT"), "Vertex project")
	location := fs.String("vertex-location", envDefault("VYQL_VERTEX_LOCATION", "global"), "Vertex location")
	creds := fs.String("vertex-credentials", defaultVertexCredentials(), "Vertex service-account JSON file; uses ADC when empty")
	model := fs.String("model", envDefault("VYQL_VERTEX_MODEL", "gemini-3.5-flash"), "Vertex model")
	contextCache := fs.Bool("vertex-context-cache", envBoolDefault("VYQL_VERTEX_CONTEXT_CACHE", true), "enable Vertex explicit context caching for repeated agentic prep prompt tokens")
	debug := fs.Bool("debug", envBool("VYQL_AGENTIC_PREP_DEBUG"), "print agentic prep debug logs to stderr")
	format := fs.String("format", "text", "output format: text | json")
	_ = fs.Parse(args)
	paths := fs.Args()
	if len(paths) == 0 {
		return fmt.Errorf("usage: vyql prep [-provider off|vertex] [-out DIR] <path>...")
	}
	out, _, err := runAgenticPrepForScan(paths, prepCLIConfig{
		OutDir:       *outDir,
		Provider:     *provider,
		Project:      *project,
		Location:     *location,
		Model:        *model,
		Creds:        *creds,
		ContextCache: *contextCache,
		Debug:        *debug,
	})
	if err != nil {
		return err
	}
	if *format == "json" {
		b, _ := json.MarshalIndent(map[string]string{"overlay": out}, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if *format != "text" {
		return fmt.Errorf("unknown -format %q (use text or json)", *format)
	}
	fmt.Println(out)
	return nil
}

func runAgenticPrepForScan(paths []string, cfg prepCLIConfig) (string, agenticprep.ScanConfig, error) {
	out := strings.TrimSpace(cfg.OutDir)
	if out == "" {
		dir, err := os.MkdirTemp("", "vyql-agentic-prep-")
		if err != nil {
			return "", agenticprep.ScanConfig{}, err
		}
		out = dir
	} else if !filepath.IsAbs(out) {
		abs, err := filepath.Abs(out)
		if err != nil {
			return "", agenticprep.ScanConfig{}, err
		}
		out = abs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if cfg.Debug {
		fmt.Fprintf(os.Stderr, "[agentic-prep] start provider=%s out=%s paths=%s\n", cfg.Provider, out, strings.Join(paths, ","))
	}

	var provider agenticprep.Provider
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "", "off", "none":
	case "vertex":
		p, err := agenticprep.NewVertexProvider(ctx, agenticprep.VertexConfig{
			Project:         cfg.Project,
			Location:        cfg.Location,
			Model:           cfg.Model,
			CredentialsFile: cfg.Creds,
			ContextCache:    cfg.ContextCache,
			Debug:           cfg.Debug,
		})
		if err != nil {
			return "", agenticprep.ScanConfig{}, err
		}
		provider = p
	default:
		return "", agenticprep.ScanConfig{}, fmt.Errorf("unknown agentic prep provider %q", cfg.Provider)
	}
	res, err := agenticprep.Prepare(ctx, paths, agenticprep.Config{
		OutDir:   out,
		Provider: provider,
		Model:    cfg.Model,
	})
	if err != nil {
		return "", res.ScanConfig, err
	}
	fmt.Fprintf(os.Stderr, "[agentic-prep] wrote %s (manifest=%s scan_config=%s languages=%d adapters=%d agent_steps=%d)\n",
		res.OutDir, filepath.Join(res.OutDir, "manifest.json"), filepath.Join(res.OutDir, "scan_config.json"), len(res.Profile.Languages), len(res.Proposal.AdapterFiles), len(res.Proposal.AgentLog))
	if strings.TrimSpace(res.ScanConfig.Profile) != "" {
		fmt.Fprintf(os.Stderr, "[agentic-prep] scan profile: %s (%s)\n", res.ScanConfig.Profile, res.ScanConfig.Reason)
	}
	for _, warning := range res.Warnings {
		fmt.Fprintf(os.Stderr, "[agentic-prep] warning: %s\n", warning)
	}
	return out, res.ScanConfig, nil
}

func envDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envBoolDefault(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	case "":
		return fallback
	default:
		return fallback
	}
}

func defaultVertexCredentials() string {
	if v := strings.TrimSpace(os.Getenv("VYQL_VERTEX_CREDENTIALS")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
}

func setOptionalEnv(key, value string) func() {
	value = strings.TrimSpace(value)
	old, had := os.LookupEnv(key)
	if value == "" {
		return func() {}
	}
	_ = os.Setenv(key, value)
	return func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	}
}
