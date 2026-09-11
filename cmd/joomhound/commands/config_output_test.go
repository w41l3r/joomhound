package commands

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/w41l3r/joomhound/internal/models"
	"github.com/w41l3r/joomhound/internal/scanner"
)

func TestConfigPrecedenceAndSafetyBoundary(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	config := `timeout: 41
threads: 20
rate-limit: 2.5
format: json
proxy:
  enabled: false
  url: http://127.0.0.1:8080
target: https://stale-target.example
brute: true
passwords: stale-passwords.txt
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	oldConfig := cfgFile
	cfgFile = configPath
	defer func() { cfgFile = oldConfig }()
	t.Setenv("JOOMHOUND_THREADS", "6")

	cmd := &cobra.Command{Use: "enum"}
	var (
		timeoutValue int
		threadsValue int
		rateValue    float64
		formatValue  string
		proxyValue   string
		targetValue  string
		bruteValue   bool
		passwords    string
	)
	cmd.Flags().IntVar(&timeoutValue, "timeout", 20, "")
	cmd.Flags().IntVar(&threadsValue, "threads", 10, "")
	cmd.Flags().Float64Var(&rateValue, "rate-limit", 10, "")
	cmd.Flags().StringVar(&formatValue, "format", "text", "")
	cmd.Flags().StringVar(&proxyValue, "proxy", "", "")
	cmd.Flags().StringVar(&targetValue, "target", "", "")
	cmd.Flags().BoolVar(&bruteValue, "brute", false, "")
	cmd.Flags().StringVar(&passwords, "passwords", "", "")

	// An explicit CLI flag must beat both environment and file values.
	if err := cmd.Flags().Set("timeout", "7"); err != nil {
		t.Fatalf("Set(timeout): %v", err)
	}
	if err := loadAndApplyConfig(cmd); err != nil {
		t.Fatalf("loadAndApplyConfig: %v", err)
	}

	if timeoutValue != 7 {
		t.Errorf("timeout = %d, want CLI value 7", timeoutValue)
	}
	if threadsValue != 6 {
		t.Errorf("threads = %d, want environment value 6", threadsValue)
	}
	if rateValue != 2.5 || formatValue != "json" {
		t.Errorf("config values not applied: rate=%v format=%q", rateValue, formatValue)
	}
	if proxyValue != "" {
		t.Errorf("legacy disabled proxy section was treated as a proxy URL: %q", proxyValue)
	}
	if targetValue != "" || bruteValue || passwords != "" {
		t.Errorf("active settings escaped the config safety boundary: target=%q brute=%v passwords=%q",
			targetValue, bruteValue, passwords)
	}
}

func TestExplicitConfigErrorsAreReturned(t *testing.T) {
	oldConfig := cfgFile
	defer func() { cfgFile = oldConfig }()

	cmd := &cobra.Command{Use: "enum"}
	var timeoutValue int
	cmd.Flags().IntVar(&timeoutValue, "timeout", 20, "")

	t.Run("missing file", func(t *testing.T) {
		cfgFile = filepath.Join(t.TempDir(), "missing.yaml")
		err := loadAndApplyConfig(cmd)
		if err == nil || !strings.Contains(err.Error(), "reading configuration") {
			t.Fatalf("error = %v, want explicit config read error", err)
		}
	})

	t.Run("invalid value", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(configPath, []byte("timeout: not-a-number\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfgFile = configPath
		err := loadAndApplyConfig(cmd)
		if err == nil || !strings.Contains(err.Error(), `invalid configuration value for "timeout"`) {
			t.Fatalf("error = %v, want typed config error", err)
		}
	})

	t.Run("malformed YAML", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(configPath, []byte("timeout: [\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfgFile = configPath
		err := loadAndApplyConfig(cmd)
		if err == nil || !strings.Contains(err.Error(), "reading configuration") {
			t.Fatalf("error = %v, want malformed YAML read error", err)
		}
	})
}

func TestResolveFormatValidatesAndDetectsConflicts(t *testing.T) {
	newCommand := func() *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("format", "", "")
		cmd.Flags().Bool("json", false, "")
		return cmd
	}

	t.Run("file extension", func(t *testing.T) {
		got, err := resolveFormat(newCommand(), "report.xml")
		if err != nil || got != "xml" {
			t.Fatalf("resolveFormat = %q, %v; want xml, nil", got, err)
		}
	})

	t.Run("file extension overrides configured default", func(t *testing.T) {
		cmd := newCommand()
		if err := cmd.Flags().Lookup("format").Value.Set("json"); err != nil {
			t.Fatalf("setting config-like default: %v", err)
		}
		got, err := resolveFormat(cmd, "report.xml")
		if err != nil || got != "xml" {
			t.Fatalf("resolveFormat = %q, %v; want xml, nil", got, err)
		}
	})

	t.Run("explicit format overrides file extension", func(t *testing.T) {
		cmd := newCommand()
		_ = cmd.Flags().Set("format", "markdown")
		got, err := resolveFormat(cmd, "report.xml")
		if err != nil || got != "markdown" {
			t.Fatalf("resolveFormat = %q, %v; want markdown, nil", got, err)
		}
	})

	t.Run("normalizes explicit value", func(t *testing.T) {
		cmd := newCommand()
		_ = cmd.Flags().Set("format", " JSON ")
		got, err := resolveFormat(cmd, "")
		if err != nil || got != "json" {
			t.Fatalf("resolveFormat = %q, %v; want json, nil", got, err)
		}
	})

	t.Run("rejects unknown value", func(t *testing.T) {
		cmd := newCommand()
		_ = cmd.Flags().Set("format", "csv")
		if _, err := resolveFormat(cmd, ""); err == nil {
			t.Fatal("resolveFormat(csv) returned nil error")
		}
	})

	t.Run("rejects unknown configured value even with known extension", func(t *testing.T) {
		cmd := newCommand()
		if err := cmd.Flags().Lookup("format").Value.Set("csv"); err != nil {
			t.Fatalf("setting config-like value: %v", err)
		}
		if _, err := resolveFormat(cmd, "report.xml"); err == nil {
			t.Fatal("resolveFormat(config csv, report.xml) returned nil error")
		}
	})

	t.Run("rejects contradictory flags", func(t *testing.T) {
		cmd := newCommand()
		_ = cmd.Flags().Set("format", "xml")
		_ = cmd.Flags().Set("json", "true")
		if _, err := resolveFormat(cmd, ""); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("error = %v, want conflicting flag error", err)
		}
	})

	t.Run("JSON CLI shorthand overrides config default", func(t *testing.T) {
		cmd := newCommand()
		if err := cmd.Flags().Lookup("format").Value.Set("xml"); err != nil {
			t.Fatalf("setting config-like default: %v", err)
		}
		_ = cmd.Flags().Set("json", "true")
		got, err := resolveFormat(cmd, "")
		if err != nil || got != "json" {
			t.Fatalf("resolveFormat = %q, %v; want json, nil", got, err)
		}
	})
}

func TestRunScanKeepsJSONStdoutMachineReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "0123456789abcdef0123456789abcdef", Value: "session", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><meta name="generator" content="Joomla! - Open Source Content Management"></head>` +
			`<body><script>window.Joomla = {};</script><img src="/media/system/images/logo.png"></body></html>`))
	}))
	defer srv.Close()

	cmd := &cobra.Command{Use: "test"}
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	oldQuiet := quiet
	quiet = false
	defer func() { quiet = oldQuiet }()

	err := runScan(cmd, scanner.ScanConfig{
		Target: srv.URL, Threads: 2, Timeout: 2 * time.Second,
		RateLimit: 100, FollowRedirects: true, Verbose: true,
	}, "", "json")
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not standalone JSON:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "JoomHound") || strings.Contains(stdout.String(), "Starting scan") {
		t.Fatalf("operational output leaked into stdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "JoomHound") || !strings.Contains(stderr.String(), "Starting scan") {
		t.Fatalf("stderr is missing banner or progress output:\n%s", stderr.String())
	}
}

func TestWriteReportUsesSeparateStatusStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("stale report"), 0o644); err != nil {
		t.Fatalf("creating existing report: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("setting unsafe existing mode: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if err := writeReport(&models.ScanResult{Target: "https://target.example"}, path, "json", &stdout, &stderr); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty for file output", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Report written") {
		t.Fatalf("stderr = %q, want report confirmation", stderr.String())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("report mode = %o, want 600", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("output directory contains temporary files: %v", entries)
	}
}

func TestStandaloneCVEFetcherReportsDiskCacheFallback(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(cachePath, []byte("file"), 0o600); err != nil {
		t.Fatalf("creating cache blocker: %v", err)
	}

	cmd := &cobra.Command{Use: "cve"}
	cmd.Flags().String("nvd-api-key", "", "")
	cmd.Flags().String("github-token", "", "")
	cmd.Flags().String("cache-dir", cachePath, "")
	cmd.Flags().Int("cache-ttl", 24, "")
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if _, err := buildStandaloneFetcher(cmd, true); err != nil {
		t.Fatalf("buildStandaloneFetcher: %v", err)
	}
	if !strings.Contains(stderr.String(), "CVE disk cache unavailable, using memory cache") {
		t.Fatalf("stderr = %q, want explicit memory-cache fallback warning", stderr.String())
	}
}
